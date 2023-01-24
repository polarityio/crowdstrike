const requestWithDefaults = require('./requestWithDefaults');
const { getLogger } = require('./logger');
const { TokenRequestError } = require('./responses');
const { getTokenFromCache, setTokenInCache } = require('./tokenCache');

const generateAccessToken = async (options) => {
  const Logger = getLogger();
  let token = getTokenFromCache(options);
  if (token) return token;

  try {
    const requestOptions = {
      uri: `${options.url}/oauth2/token`,
      method: 'POST',
      json: true,
      form: {
        client_id: options.id,
        client_secret: options.secret
      }
    };

    const response = await requestWithDefaults.request(requestOptions);
    const { body } = response;

    if (response.statusCode === 201 && body.access_token) {
      setTokenInCache(options, body.access_token);
      return body.access_token;
    } else {
      Logger.error(
        { body, status: response.statusCode },
        'Unable to get auth token.  Check your credentials.'
      );
      let detailMessage = `Unexpected error getting auth token (status: ${response.statusCode})`;

      if (response.statusCode === 403) {
        detailMessage = `The provided Client Secret does not match the provided Client Id`;
      } else if (response.statusCode === 401 || response.statusCode === 400) {
        detailMessage = `The provided Client ID is not valid (status: ${response.statusCode})`;
      }

      throw new TokenRequestError(detailMessage, response.statusCode, response.body, {
        ...requestOptions,
        form: {
          client_id: '********',
          client_secret: '********'
        }
      });
    }
  } catch (err) {
    err.source = 'generateAccessToken';
    throw err;
  }
};

module.exports = generateAccessToken;
