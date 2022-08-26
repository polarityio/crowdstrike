const fs = require('fs');
const request = require('postman-request');
const config = require('../config/config');
const _ = require('lodash');
const { generateAccessToken, invalidateToken } = require('./getToken');
const { RequestError } = require('./responses');
const _configFieldIsValid = (field) => typeof field === 'string' && field.length > 0;

let Logger;
let requestWithDefaults;
let requestRetryCount = 0;

// Note that CrowdStrike will return a 403 both if the token is expired and if the
// token does not have correct permissions. This makes it difficult to differentiate between
// when we need to refresh the token, and when the token does not have correct permissions and
// will never work.
const EXPIRED_BEARER_TOKEN_HTTP_CODE = 403;
const INVALID_BEARER_TOKEN_HTTP_CODE = 401;
const MAX_AUTH_RETRIES = 1;

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

  requestWithDefaults = (requestOptions) =>
    new Promise((resolve, reject) => {
      _defaultsRequest(requestOptions, (err, res, body) => {
        if (err) return reject(err);
        const response = { ...res, body };

        Logger.trace({ response }, 'Response in requestWithDefaults');

        try {
          checkForStatusError(response, requestOptions, Logger);
        } catch (err) {
          reject(err);
        }

        resolve(response);
      });
    });

  Logger.trace({ requestWithDefaults }, 'requests with defaults');
  return requestWithDefaults;
};

const checkForStatusError = (response, requestOptions, Logger) => {
  const statusCode = response.statusCode;

  if (![200, 201, 202, 404, 409, 403, 401, 429, 500, 502, 504].includes(statusCode)) {
    const errorMessage = _.get(response, 'body.errors.0.message', 'Request Error');
    const requestError = new RequestError(errorMessage, statusCode, response.body, {
      ...requestOptions,
      headers: '********'
    });
    throw requestError;
  }
};

const authenticatedRequest = async (
  requestWithDefaults,
  requestOptions,
  options,
  Logger
) => {
  try {
    Logger.trace({ HERE: generateAccessToken });
    const tokenResponse = await generateAccessToken(requestWithDefaults, options, Logger);
    requestOptions.headers = { authorization: `Bearer ${tokenResponse}` };
    const response = await requestWithDefaults(requestOptions);
    const statusCode = response.statusCode;

    if (requestRetryCount > MAX_AUTH_RETRIES) {
      const errorMessage = _.get(
        response,
        'body.errors.0.message',
        `Attempted to authenticate ${MAX_AUTH_RETRIES} times but failed authentication`
      );
      throw new RequestError(errorMessage, statusCode, response.body, {
        ...requestOptions,
        headers: '********'
      });
    }

    if (
      statusCode === EXPIRED_BEARER_TOKEN_HTTP_CODE ||
      statusCode === INVALID_BEARER_TOKEN_HTTP_CODE
    ) {
      Logger.trace(
        { statusCode, requestRetryCount },
        'Invalid or expired token. Invalidating and re-requesting'
      );
      invalidateToken(options);
      requestRetryCount++;
      await authenticatedRequest(requestWithDefaults, requestOptions, options, Logger);
      return;
    }
    return response;
  } catch (err) {
    throw err;
  } finally {
    // reset retry count everytime we have a successful request
    requestRetryCount = 0;
  }
};

module.exports = {
  setRequestWithDefaults,
  authenticatedRequest
};
