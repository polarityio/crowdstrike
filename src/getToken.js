const tokenCache = new Map();

const generateAccessToken = async (requestWithDefaults, options, Logger) => {
  let token = getTokenFromCache(options);
  if (token) return token;

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

    if (response.statusCode === 201 && body.access_token) {
      setTokenInCache(options, body.access_token, Logger);
      return response.body.access_token;
    }
  } catch (err) {
    err.source = 'generateAccessToken'
    throw err;
  }
};

const invalidateToken = (options) => {
  tokenCache.delete(_getTokenKey(options));
};

const getTokenFromCache = (options) => tokenCache.get(_getTokenKey(options));

const setTokenInCache = (options, token) => tokenCache.set(_getTokenKey(options), token);

const _getTokenKey = (options) => options.url + options.id + options.secret;

module.exports = {
  generateAccessToken,
  invalidateToken
};
