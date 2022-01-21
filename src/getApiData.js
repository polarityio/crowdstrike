const generateAccessToken = require('./getToken');
const { polarityResponse } = require('./responses');
const { searchDetects, getDetects } = require('./detects');

const getApiData = async (requestWithDefaults, entity, options, Logger) => {
  try {
    const results = await generateAccessToken(requestWithDefaults, options, Logger);
    const token = results.body.access_token;
    
    const detects = await getDetects(requestWithDefaults, token, entity, options, Logger);

    return polarityResponse(entity, detects, Logger);
  } catch (err) {
    throw err;
  }
};

module.exports = getApiData;
