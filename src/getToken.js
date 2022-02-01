const tokenCache = new Map();

const generateAccessToken = async (requestWithDefaults, options, Logger) => {
  let token = getTokenFromCache(options);

  if (token) {
    return token;
  }

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

    const { body } = response;

    Logger.trace({ TOKEN_RESPONSE: response });

    if (response.statusCode === 201 && body.access_token) {
      Logger.trace({ CACHE: response });
      setTokenInCache(options, body.access_token, Logger);
      Logger.trace({ CACHE: tokenCache });
      return response.body.access_token;
    }
  } catch (err) {
    Logger.trace({ err }, 'err in generating tokens');
  }
};

const getTokenFromCache = (options, Logger) => {
  return tokenCache.get(_getTokenKey(options, Logger));
};

const setTokenInCache = (options, token, Logger) => {
  tokenCache.set(_getTokenKey(options, Logger), token);
};

const _getTokenKey = (options, Logger) => {
  return options.url + options.id + options.secret;
};
//create a new token,
// invalid token
// expired token

module.exports = generateAccessToken;
