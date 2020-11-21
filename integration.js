const fs = require('fs');
const config = require('./config/config');
const async = require('async');
const request = require('request');

const MAX_AUTH_RETRIES = 2;
// Older versions of the Crowdstrike API would return a 403 if the bearer token was expired
// newer versions now return a 401. We check for both just in case.
const EXPIRED_BEARER_TOKEN_HTTP_CODE = 403;
const INVALID_BEARER_TOKEN_HTTP_CODE = 401;
const tokenCache = new Map();
const SEVERITY_LEVELS = {
  Critical: '"Critical"',
  High: '"High","Critical"',
  Medium: '"Medium","High","Critical"',
  Low: '"Low","Medium","High","Critical"'
};
let Logger;
let requestWithDefaults;
let authenticatedRequest;

/**
 * Creates the query string portion of the search request.  Note that while there is a full text search capability in
 * the Crowdstrike API, running a full text search is too slow to use.  As a result, we are currently filtering based
 * on different targeted fields based on the entity type to improve search performance.
 *
 * @param entityObj
 * @param options
 * @returns {} QueryString object for request
 * @private
 */
function _getQuery(entityObj, options) {
  let statuses = options.detectionStatuses.map((statusObj) => {
    // statuses need to be in double quotes
    return `"${statusObj.value}"`;
  });

  let severityLevels = SEVERITY_LEVELS[options.minimumSeverity.value];

  let type = 'sha256';
  if (entityObj.isMD5) {
    type = 'md5';
  }
  let filter = `+status:[${statuses.toString()}]+max_severity_displayname:[${severityLevels}]`;

  return {
    limit: 10,
    // ioc_value needs to be in double quotes, Crowdstrike requires that hashes are searched in lowercase
    filter: `(behaviors.ioc_value:"${entityObj.value.toLowerCase()}"${filter}),(behaviors.${type}:"${entityObj.value.toLowerCase()}"${filter})`
  };
}

function searchDetects(entity, options, cb) {
  let requestOptions = {
    uri: `${options.url}/detects/queries/detects/v1`,
    qs: _getQuery(entity, options),
    method: 'GET'
  };

  Logger.trace(requestOptions, 'searchDetects request options');

  authenticatedRequest(options, requestOptions, (err, response, body) => {
    if (err) {
      return cb(err);
    }

    Logger.trace(body, 'result of searchDetects');

    if (body.resources.length > 0) {
      cb(null, {
        entity: entity,
        data: {
          summary: [`${body.resources.length} detections`],
          details: {
            meta: {
              totalResults: body.meta.pagination.total
            },
            resourceIds: body.resources
          }
        }
      });
    } else {
      // Cache as a miss
      cb(null, {
        entity: entity,
        data: null
      });
    }
  });
}

function getDetects(detectIds, options, cb) {
  let requestOptions = {
    uri: `${options.url}/detects/entities/summaries/GET/v1`,
    body: {
      ids: detectIds
    },
    json: true,
    method: 'POST'
  };

  authenticatedRequest(options, requestOptions, (err, response, body) => {
    if (err) {
      return cb(err);
    }

    let detects = body.resources.map((resource) => {
      let split = resource.detection_id.split(':');
      resource.__url = `https://falcon.crowdstrike.com/activity/detections/detail/${split[1]}/${split[2]}`;
      return resource;
    });

    Logger.debug({ detections: detects }, 'getDetects() return result');

    cb(null, detects);
  });
}

function generateAccessToken(options, cb) {
  let token = getTokenFromCache(options);
  if (token) {
    Logger.trace({ token: token }, 'Returning token from Cache');
    cb(null, token);
  } else {
    Logger.trace('generating access token');
    requestWithDefaults(
      {
        uri: `${options.url}/oauth2/token`,
        method: 'POST',
        json: true,
        form: {
          client_id: options.id,
          client_secret: options.secret
        }
      },
      (err, response, body) => {
        if (err) {
          return cb({
            detail: 'HTTP Request Error when generating OAuth Token',
            err: err
          });
        }

        if (response.statusCode === 201 && body.access_token) {
          setTokenInCache(options, body.access_token);
          cb(null, body.access_token);
        } else {
          cb({
            response: response,
            detail: 'Failed to retrieve auth token'
          });
        }
      }
    );
  }
}

function doLookup(entities, options, cb) {
  const lookupResults = [];

  async.each(
    entities,
    (entity, next) => {
      searchDetects(entity, options, (err, result) => {
        if (err) {
          return next(err);
        }

        Logger.debug({ result }, 'Received Search Detect Result');
        lookupResults.push(result);
        next(null);
      });
    },
    (err) => {
      Logger.trace({ lookupResults: lookupResults }, 'Returning lookup results to client');
      cb(err, lookupResults);
    }
  );
}

function onDetails(lookupObject, options, cb) {
  getDetects(lookupObject.data.details.resourceIds, options, (err, detects) => {
    if (err) {
      return cb(err);
    }

    lookupObject.data.details.detections = detects;

    cb(null, lookupObject.data);
  });
}

function startup(logger) {
  Logger = logger;
  let requestOptions = {};

  if (typeof config.request.cert === 'string' && config.request.cert.length > 0) {
    requestOptions.cert = fs.readFileSync(config.request.cert);
  }

  if (typeof config.request.key === 'string' && config.request.key.length > 0) {
    requestOptions.key = fs.readFileSync(config.request.key);
  }

  if (typeof config.request.passphrase === 'string' && config.request.passphrase.length > 0) {
    requestOptions.passphrase = config.request.passphrase;
  }

  if (typeof config.request.ca === 'string' && config.request.ca.length > 0) {
    requestOptions.ca = fs.readFileSync(config.request.ca);
  }

  if (typeof config.request.proxy === 'string' && config.request.proxy.length > 0) {
    requestOptions.proxy = config.request.proxy;
  }

  if (typeof config.request.rejectUnauthorized === 'boolean') {
    requestOptions.rejectUnauthorized = config.request.rejectUnauthorized;
  }

  requestOptions.json = true;
  requestWithDefaults = request.defaults(requestOptions);

  authenticatedRequest = (options, requestOptions, cb, requestCounter = 0) => {
    if (requestCounter === MAX_AUTH_RETRIES) {
      // We reached the maximum number of auth retries
      return cb({
        detail: `Attempted to authenticate ${MAX_AUTH_RETRIES} times but failed authentication`
      });
    }

    generateAccessToken(options, function (err, token) {
      if (err) {
        Logger.error({ err: err }, 'Error getting token');
        return cb({
          err: err,
          detail: 'Error creating authentication token'
        });
      }

      requestOptions.headers = { authorization: `bearer ${token}` };

      requestWithDefaults(requestOptions, (err, resp, body) => {
        if (err) {
          return cb(err, resp, body);
        }

        if (resp.statusCode === EXPIRED_BEARER_TOKEN_HTTP_CODE || resp.statusCode === INVALID_BEARER_TOKEN_HTTP_CODE) {
          // Unable to authenticate so we attempt to get a new token
          invalidateToken(options);
          authenticatedRequest(options, requestOptions, cb, ++requestCounter);
          return;
        }

        let restError = handleRestErrors(resp);
        if (restError) {
          return cb(restError);
        }

        cb(null, resp, body);
      });
    });
  };
}

function getTokenFromCache(options) {
  return tokenCache.get(_getTokenKey(options));
}

function setTokenInCache(options, token) {
  Logger.trace({ token: token }, 'Set Token for Auth');
  tokenCache.set(_getTokenKey(options), token);
}

function invalidateToken(options) {
  Logger.trace('Invalidating Token');
  tokenCache.delete(_getTokenKey(options));
}

function _getTokenKey(options) {
  return options.url + options.id + options.secret;
}

function handleRestErrors(response, body) {
  switch (response.statusCode) {
    case 200:
      return;
    case 201:
      return;
    case 401:
      return _createJsonErrorPayload('Permission Denied', null, '401', '1', 'Unauthorized', {
        body,
        response
      });
    case 403:
      return _createJsonErrorPayload('Authentication Token is Invalid or Expired', null, '403', '1', 'Forbidden', {
        body,
        response
      });
    case 404:
      return _createJsonErrorPayload('Object not found', null, '404', '1', 'Not Found', {
        body,
        response
      });
    case 400:
      return _createJsonErrorPayload(
        'Invalid Search, please check search parameters',
        null,
        '400',
        '2',
        'Bad Request',
        {
          body,
          response
        }
      );
    case 429:
      return _createJsonErrorPayload('Too Many Requests', null, '409', '3', 'Too Many Requests', {
        body,
        response
      });
    case 500:
      return _createJsonErrorPayload(
        'Internal Server error, please check your instance',
        null,
        '500',
        '5',
        'Internal error',
        {
          body,
          response
        }
      );
  }

  return _createJsonErrorPayload(
    'Unexpected HTTP Response Status Code',
    null,
    response.statusCode,
    '7',
    'Unexpected HTTP Error',
    {
      body,
      response
    }
  );
}

// function that takes the ErrorObject and passes the error message to the notification window
function _createJsonErrorPayload(msg, pointer, httpCode, code, title, meta) {
  return {
    errors: [_createJsonErrorObject(msg, pointer, httpCode, code, title, meta)]
  };
}

function _createJsonErrorObject(msg, pointer, httpCode, code, title, meta) {
  let error = {
    detail: msg,
    status: httpCode.toString(),
    title: title,
    code: 'RES' + code.toString()
  };

  if (pointer) {
    error.source = {
      pointer: pointer
    };
  }

  if (meta) {
    error.meta = meta;
  }

  return error;
}

function validateStringOption(errors, options, optionName, errMessage) {
  if (
    typeof options[optionName].value !== 'string' ||
    (typeof options[optionName].value === 'string' && options[optionName].value.length === 0)
  ) {
    errors.push({
      key: optionName,
      message: errMessage
    });
  }
}

function validateTrailingSlash(errors, options, optionName, errMessage) {
  if (typeof options[optionName].value === 'string' && options[optionName].value.trim().endsWith('/')) {
    errors.push({
      key: optionName,
      message: errMessage
    });
  }
}

function validateOptions(options, callback) {
  let errors = [];

  validateStringOption(errors, options, 'url', 'You must provide the Crowdstrike API url.');
  validateTrailingSlash(errors, options, 'url', 'The url cannot end with a forward slash ("/").');
  validateStringOption(errors, options, 'id', 'You must provide a Client ID.');
  validateStringOption(errors, options, 'secret', 'You must provide a Client Secret.');

  callback(null, errors);
}

module.exports = {
  doLookup: doLookup,
  startup: startup,
  validateOptions: validateOptions,
  onDetails: onDetails,
  __generateAccessToken: generateAccessToken,
  __searchDetects: searchDetects,
  __getDetects: getDetects
};
