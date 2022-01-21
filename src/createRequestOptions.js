const fs = require('fs');
const request = require('postman-request');
const config = require('../config/config');

const _configFieldIsValid = (field) => typeof field === 'string' && field.length > 0;

let Logger;
let requestWithDefaults;

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

        Logger.trace({ response }, 'Response');

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

const checkForStatusError = (response, requestOptions) => {
  const statusCode = response.statusCode;

  if (![200, 201, 429, 500, 502, 504].includes(statusCode)) {
    const requestError = Error('Request Error');
    requestError.status = statusCode;
    requestError.description = JSON.stringify(response.body);
    requestError.requestOptions = requestOptions;
    throw requestError;
  }
};

module.exports = setRequestWithDefaults;

// let requestOptions = {};

// if (typeof config.request.cert === 'string' && config.request.cert.length > 0) {
//   requestOptions.cert = fs.readFileSync(config.request.cert);
// }

// if (typeof config.request.key === 'string' && config.request.key.length > 0) {
//   requestOptions.key = fs.readFileSync(config.request.key);
// }

// if (typeof config.request.passphrase === 'string' && config.request.passphrase.length > 0) {
//   requestOptions.passphrase = config.request.passphrase;
// }

// if (typeof config.request.ca === 'string' && config.request.ca.length > 0) {
//   requestOptions.ca = fs.readFileSync(config.request.ca);
// }

// if (typeof config.request.proxy === 'string' && config.request.proxy.length > 0) {
//   requestOptions.proxy = config.request.proxy;
// }

// if (typeof config.request.rejectUnauthorized === 'boolean') {
//   requestOptions.rejectUnauthorized = config.request.rejectUnauthorized;
// }

// requestOptions.json = true;
// requestWithDefaults = request.defaults(requestOptions);

// authenticatedRequest = (options, requestOptions, cb, requestCounter = 0) => {
//   if (requestCounter === MAX_AUTH_RETRIES) {
//     // We reached the maximum number of auth retries
//     return cb({
//       detail: `Attempted to authenticate ${MAX_AUTH_RETRIES} times but failed authentication`
//     });
//   }

//   generateAccessToken(options, function (err, token) {
//     if (err) {
//       Logger.error({ err: err }, 'Error getting token');
//       return cb({
//         err: err,
//         detail: 'Error creating authentication token'
//       });
//     }

//     requestOptions.headers = { authorization: `bearer ${token}` };

//     requestWithDefaults(requestOptions, (err, resp, body) => {
//       if (err) {
//         return cb(err, resp, body);
//       }

//       if (resp.statusCode === EXPIRED_BEARER_TOKEN_HTTP_CODE || resp.statusCode === INVALID_BEARER_TOKEN_HTTP_CODE) {
//         // Unable to authenticate so we attempt to get a new token
//         invalidateToken(options);
//         authenticatedRequest(options, requestOptions, cb, ++requestCounter);
//         return;
//       }

//       let restError = handleRestErrors(resp);

//       if (restError) {
//         return cb(restError);
//       }

//       cb(null, resp, body);
//     });
//   });
// };
