const _ = require('lodash');
const { getDetects } = require('./detects');
const { getDevices } = require('./devices');
const { getIocIndicators } = require('./iocs');
const {
  polarityResponse,
  retryablePolarityResponse,
  RetryRequestError
} = require('./responses');
const { getLogger } = require('./logger');

const getApiData = async (entity, options) => {
  const Logger = getLogger();
  try {
    const detectionData = await getDetects(entity, options);
    Logger.trace({ detectionData }, 'detectionData API data');

    const deviceData = await getDevices(entity, options);
    Logger.trace({ deviceData }, 'devices API data');

    let iocData = { indicators: null, statusCode: 400 };

    if (options.searchIoc) {
      iocData = await getIocIndicators(entity, options);
      Logger.trace({ iocData }, 'IOC API data');
    }

    const apiData = {
      hosts: deviceData,
      events: detectionData,
      iocs: iocData
    };

    return apiData;
  } catch (error) {
    throw error;
  }
};

const buildResponse = async (entity, options) => {
  const Logger = getLogger();
  try {
    const apiData = await getApiData(entity, options);
    Logger.trace({ apiData }, 'api result');
    return polarityResponse(entity, apiData);
  } catch (err) {
    if (err instanceof RetryRequestError) {
      return retryablePolarityResponse(entity, err);
    } else {
      throw err;
    }
  }
};

module.exports = buildResponse;
