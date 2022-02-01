const fs = require('fs');
const request = require('postman-request');
const config = require('../config/config');
const generateAccessToken = require('./getToken');

const _configFieldIsValid = (field) => typeof field === 'string' && field.length > 0;

let Logger;
let requestWithDefaults;

const EXPIRED_BEARER_TOKEN_HTTP_CODE = 403;
const INVALID_BEARER_TOKEN_HTTP_CODE = 401;
const MAX_AUTH_RETRIES = 2;

const setRequestWithDefaults = (Logger) => {
  const {
    request: { ca, cert, key, passphrase, rejectUnauthorized, proxy }
  } = config;

  const defaults = {
    ...(_configFieldIsValid(ca) && { ca: fs.readFileSync(ca) }),
    ...(_configFieldIsValid(cert) && { cert: fs.readFileSync(cert) }),
    ...(_configFieldIsValid(key) && { key: fs.readFileSync(key) }),
    ...(_configFieldIsValid(passphrase) && { passphrase }),
    ...(_configFieldIsValid(proxy) && { proxy }),
    ...(typeof rejectUnauthorized === 'boolean' && { rejectUnauthorized })
  };

  const _defaultsRequest = request.defaults(defaults);

  Logger.trace({ _defaultsRequest }, 'Defaults Request');

  requestWithDefaults = (requestOptions) =>
    new Promise((resolve, reject) => {
      _defaultsRequest(requestOptions, (err, res, body) => {
        if (err) return reject(err);
        const response = { ...res, body };

        Logger.trace({ response }, 'Response in requestWithDefaults');

        try {
          checkForStatusError(response, requestOptions);
        } catch (err) {
          reject(err);
        }

        resolve(response);
      });
    });

  Logger.trace({ requestWithDefaults }, 'requests with defaults');
  return requestWithDefaults;
};

const authenticatedRequest = async (requestWithDefaults, requestOptions, options, Logger) => {
  // startup sets requestwith defaults,
  // if (requestCount === MAX_AUTH_RETRIES) {
  //   throw new Error(`Attempted to authenticate ${MAX_AUTH_RETRIES} times but failed authentication`);
  // }

  try {
    const tokenResponse = await generateAccessToken(requestWithDefaults, options, Logger);
    Logger.trace({ TOKEN: tokenResponse });
    requestOptions.headers = { authorization: `Bearer ${tokenResponse}` };

    const response = await requestWithDefaults(requestOptions);

    if (
      response.statusCode === EXPIRED_BEARER_TOKEN_HTTP_CODE ||
      response.statusCode === INVALID_BEARER_TOKEN_HTTP_CODE
    ) {
      invalidateToken(options);
      // requestCount++;
      authenticatedRequest(requestWithDefaults, requestOptions, options, Logger);
      return;
    }

    return response;
  } catch (err) {
    throw err;
  }
};

const checkForStatusError = (response, requestOptions) => {
  const statusCode = response.statusCode;

  if (![200, 201, 404, 429, 500, 502, 504].includes(statusCode)) {
    // possibly handle 404 differently
    const requestError = Error('Request Error');
    requestError.status = statusCode;
    requestError.description = JSON.stringify(response.body);
    requestError.requestOptions = requestOptions;
    throw requestError;
  }
};

const getTokenFromCache = (options) => {
  return tokenCache.get(_getTokenKey(options));
};

const setTokenInCache = (options, token) => {
  tokenCache.set(_getTokenKey(options), token);
};

const invalidateToken = (options) => {
  tokenCache.delete(_getTokenKey(options));
};

const _getTokenKey = (options) => {
  return options.url + options.id + options.secret;
};

module.exports = {
  setRequestWithDefaults,
  authenticatedRequest
};

// in a list of ids,  a request is made for each id
// if one of the ids does not match it will throw a 400
