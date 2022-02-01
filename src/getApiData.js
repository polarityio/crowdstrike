const _ = require('lodash');
const generateAccessToken = require('./getToken');
const { getDetects } = require('./detects');
const { getDevices } = require('./devices');
const { polarityResponse, polarityError, retryablePolarityResponse } = require('./responses');

const getApiData = async (authenticatedRequest, requestWithDefaults, entity, options, Logger) => {
  let devices;
  try {
    const detections = await getDetects(authenticatedRequest, requestWithDefaults, entity, options, Logger);

    Logger.trace({ detections }, 'detections API data');

    if (options.searchIoc) {
      devices = await getDevices(authenticatedRequest, requestWithDefaults, entity, options, Logger);
      Logger.trace({ devices }, 'Devices API data');
    }

    const apiData = { devices: devices, detections: detections };
    return apiData;
  } catch (err) {
    throw err;
  }
};

const buildResponse = async (authenticatedRequest, requestWithDefaults, entity, options, Logger) => {
  try {
    const apiData = await getApiData(authenticatedRequest, requestWithDefaults, entity, options, Logger);

    Logger.trace({ apiData }, 'API RESULT');

    // return apiData.statusCode === 200 ? polarityResponse(entity, apiData, Logger) : retryablePolarityResponse(entity);
    return polarityResponse(entity, apiData, Logger);
  } catch (err) {
    const isConnectionReset = _.get(err, 'code', '') === 'ECONNRESET';
    if (isConnectionReset) return retryablePolarityResponse(entity);
    else throw polarityError(err);
  }
};

module.exports = buildResponse;
