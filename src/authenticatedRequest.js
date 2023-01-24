/*
 * Copyright (c) 2022, Polarity.io, Inc.
 */

const _ = require('lodash');
const generateAccessToken = require('./generateAccessToken');
const { invalidateToken } = require('./tokenCache');
const { RequestError, RetryRequestError } = require('./responses');
const requestWithDefaults = require('./requestWithDefaults');
const { getLogger } = require('./logger');

// CrowdStrike will return a 401 when the token expires.  Each call to the auth endpoint
// with generate a valid token which expires after 30 minutes.  When that expiration happens
// any REST calls using that token return a 401.
const HTTP_CODE_EXPIRED_BEARER_TOKEN_401 = 401;

// CrowdStrike will return a 403 if a token does not have proper permissions (i.e., the token does
// not have the correct roles applied for the request it's trying to make)
// CrowdStrike will also return a 403 for a token that revoked via the `/revoke` endpoint
// Note that revoking a token causes a 403 while a token expiring "naturally" results in a 401
// It is possible that a revoked token that has expired will eventually return a 401 but that has
// not been tested.
const HTTP_CODE_TOKEN_MISSING_PERMISSIONS_OR_REVOKED_403 = 403;

// CrowdStrike will occasionally return a 500 error when it is overloaded with requests
// In previous versions we also caught 502, and 504 responses so adding those here
// even though these are not documented error codes.
const HTTP_CODE_SERVER_LIMIT_500 = 500;
const HTTP_CODE_SERVER_LIMIT_502 = 502;
const HTTP_CODE_SERVER_LIMIT_504 = 504;

// CrowdStrike will return a 429 error code if you hit an API search limit
const HTTP_CODE_API_LIMIT_REACHED_429 = 429;

// CrowdStrike returns 200 and 201 requests for successful searches and actions
const HTTP_CODE_SUCCESS_200 = 200;
const HTTP_CODE_SUCCESS_201 = 201;
const HTTP_CODE_SUCCESS_202 = 202;

const MAX_AUTH_RETRIES = 1;

// class NetworkError extends Error {
//   constructor(message, code) {
//     super(message);
//     this.code = code;
//   }
// }

async function authenticatedRequest(requestOptions, options, requestRetryCount = 0) {
  const Logger = getLogger();
  try {
    Logger.trace({ requestRetryCount, requestOptions }, 'Calling authenticatedRequest');
    // If the user has invalid credentials `generateAccessToken` will throw a
    // TokenRequestError.
    const tokenResponse = await generateAccessToken(options);
    //throw new NetworkError('This is the message', 'ETIMEDOUT');
    requestOptions.headers = { authorization: `Bearer ${tokenResponse}` };
    const response = await requestWithDefaults.request(requestOptions);
    const statusCode = response.statusCode;

    // First check for a successful response and if it looks successful return the result
    if (
      statusCode === HTTP_CODE_SUCCESS_200 ||
      statusCode === HTTP_CODE_SUCCESS_201 ||
      statusCode === HTTP_CODE_SUCCESS_202
    ) {
      return response;
    }

    // Now we start dealing with various error conditions
    // If we have had to retry the request more than the MAX_AUTH_RETRIES then we have failed to authenticate
    // and need to return an error.
    if (requestRetryCount >= MAX_AUTH_RETRIES) {
      if (statusCode === HTTP_CODE_TOKEN_MISSING_PERMISSIONS_OR_REVOKED_403) {
        throw new RequestError(
          'Provided Client ID and Secret do not have proper permissions',
          statusCode,
          response.body,
          {
            ...requestOptions,
            headers: '********'
          }
        );
      } else {
        const errorMessage = _.get(
          response,
          'body.errors.0.message',
          `Attempted to authenticate ${
            MAX_AUTH_RETRIES + 1
          } times but failed authentication`
        );
        throw new RequestError(errorMessage, statusCode, response.body, {
          ...requestOptions,
          headers: '********'
        });
      }
    }

    // Now we check to see if the auth failed because of an expired token or a token missing permissions
    // Note that for tokens missing permissions, we will retry the request until we hit the MAX_AUTH_RETRIES
    // at which point we will let the user know they are missing permissions.
    if (
      statusCode === HTTP_CODE_EXPIRED_BEARER_TOKEN_401 ||
      statusCode === HTTP_CODE_TOKEN_MISSING_PERMISSIONS_OR_REVOKED_403
    ) {
      Logger.trace(
        { statusCode, requestRetryCount },
        'Invalid or expired token. Invalidating and re-requesting'
      );
      invalidateToken(options);
      return await authenticatedRequest(requestOptions, options, ++requestRetryCount);
    } else if (
      statusCode === HTTP_CODE_SERVER_LIMIT_500 ||
      statusCode === HTTP_CODE_SERVER_LIMIT_502 ||
      statusCode === HTTP_CODE_SERVER_LIMIT_504
    ) {
      // Next we check for codes where we want to let the user retry the search.  This special RetryRequestError
      // is used to indicate we encountered an error but the user should be allowed to retry the request.  Sometimes
      // when CrowdStrike gets overloaded it returns a 500.  In these cases we let the user retry their search.
      throw new RetryRequestError(
        'The CrowdStrike API server experienced a temporary error',
        statusCode,
        response.body,
        {
          ...requestOptions,
          headers: '********'
        }
      );
    } else if (statusCode === HTTP_CODE_API_LIMIT_REACHED_429) {
      // If an API limit is hit the API will return a 429 status code which we check for here and then let the
      // user retry the search.

      const retryError = new RetryRequestError(
        'Temporary API Search Limit Reached',
        statusCode,
        response.body,
        {
          ...requestOptions,
          headers: '********'
        }
      );

      retryError.meta = {
        rateLimitLimit: response.headers['X-Ratelimit-Limit'],
        rateLimitRemaining: response.headers['X-Ratelimit-Remaining']
      };

      throw retryError;
    } else {
      // Return a generic error at this point
      throw new RequestError(
        `Unexpected HTTP status code received (${statusCode})`,
        statusCode,
        response.body,
        {
          ...requestOptions,
          headers: '********'
        }
      );
    }
  } catch (err) {
    // In some cases if the REST API is overloaded the API can return an ETIMEDOUT or
    // an ECONNRESET.  We catch these and return a RetryRequestError
    const code = _.get(err, 'code', '');
    const isConnectionTimeout = code === 'ETIMEDOUT';
    const isConnectionReset = code === 'ECONNRESET';
    if (isConnectionReset || isConnectionTimeout) {
      throw new RetryRequestError(
        'The CrowdStrike API server experienced a connection error.',
        code,
        null,
        {
          ...requestOptions,
          headers: '********'
        }
      );
    } else {
      throw err;
    }
  }
}

module.exports = authenticatedRequest;
