const generateAccessToken = require('./getToken');
const { polarityResponse } = require('./responses');
const { getDevices } = require('./devices');
const { getDetects } = require('./detects');

const getApiData = async (requestWithDefaults, entity, options, Logger) => {
  let devices;
  try {
    const response = await generateAccessToken(requestWithDefaults, options, Logger);
    const token = response.body.access_token;

    const detects = await getDetects(requestWithDefaults, token, entity, options, Logger);

    Logger.trace({ detects }, 'Detects API data');

    // if (options.searchIoc) {
    // devices = await getDevices(requestWithDefaults, token, entity, options, Logger);

    Logger.trace({ devices }, 'Devices API data');
    // }

    // const apiData = { devices, detects };

    // return polarityResponse(entity, apiData, Logger);
  } catch (err) {
    throw err;
  }
};

module.exports = getApiData;
