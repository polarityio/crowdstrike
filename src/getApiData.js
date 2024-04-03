const _ = require('lodash');
const getAlerts = require('./getAlerts');
const { getDevices } = require('./devices');
const getIocIndicators = require('./iocs');
const {
  polarityResponse,
  retryablePolarityResponse,
  RetryRequestError
} = require('./responses');
const { getLogger } = require('./logger');

const getApiData = async (entity, options) => {
  const Logger = getLogger();
  try {
    const alertData = await getAlerts(entity, options);
    Logger.trace({ alertData }, 'alertData API data');

    const deviceData = await getDevices(entity, options);
    Logger.trace({ deviceData }, 'devices API data');

    let iocData = { indicators: null, statusCode: 400 };

    if (options.searchIoc) {
      iocData = await getIocIndicators(entity, options);
      Logger.trace({ iocData }, 'IOC API data');
    }

    return {
      hosts: deviceData,
      events: alertData,
      iocs: iocData
    };
  } catch (error) {
    throw error;
  }
};

const buildResponse = async (entity, options) => {
  const Logger = getLogger();
  try {
    const apiData = await getApiData(entity, options);
    Logger.trace({ apiData }, 'api result');
    return polarityResponse(entity, apiData, options);
  } catch (err) {
    if (err instanceof RetryRequestError) {
      return retryablePolarityResponse(entity, err);
    } else {
      throw err;
    }
  }
};

module.exports = buildResponse;
