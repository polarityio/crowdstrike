const generateAccessToken = async (requestWithDefaults, options, cache, Logger) => {
  let token = getTokenFromCache(options, cache);
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
      setTokenInCache(options, body.access_token, cache, Logger);
      return response.body.access_token;
    }
  } catch (err) {
    Logger.trace({ err }, 'err in generating tokens');
    throw err;
  }
};

const getTokenFromCache = (options, cache) => cache.get(_getTokenKey(options));

const setTokenInCache = (options, token, cache) =>
  cache.set(_getTokenKey(options), token);

const _getTokenKey = (options) => options.url + options.id + options.secret;

module.exports = generateAccessToken;
