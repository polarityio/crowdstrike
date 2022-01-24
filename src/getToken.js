const tokenCache = new Map();
const { polarityError } = require('./responses');

// const EXPIRED_BEARER_TOKEN_HTTP_CODE = 403;
// const INVALID_BEARER_TOKEN_HTTP_CODE = 401;
// HANDLE THIS NOT GETTING A TOKEN LOGIC

const generateAccessToken = async (requestWithDefaults, options, Logger) => {
  // let token = getTokenFromCache(options);

  // if (token) {
  //   return token;
  // }

  try {
    const response = await requestWithDefaults({
      uri: `${options.url}/oauth2/token`,
      method: 'POST',
      json: true,
      form: {
        client_id: options.id,
        client_secret: options.secret
      }
    });

    Logger.trace({ response }, 'Token ');

    const { body } = response;

    if (response.statusCode === 201 && body.access_token) {
      setTokenInCache(options, body.access_token);
      return response;
    } else {
      throw new Error('Failed to retrieve auth token'); //NEED TO HANDLE NOT GETTING A TOKEN
    }
  } catch (err) {
    Logger.trace({ err }, 'err in generating tokens');
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

module.exports = generateAccessToken;
