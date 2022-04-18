const _ = require('lodash');
const { getDetects } = require('./detects');
const { getDevices } = require('./devices');
const { polarityResponse, polarityError, retryablePolarityResponse, parseErrorToReadableJSON } = require('./responses');

const getApiData = async (authenticatedRequest, requestWithDefaults, entity, options, Logger) => {
  let deviceData;
  try {
    const detectionData = await getDetects(authenticatedRequest, requestWithDefaults, entity, options, Logger);
    Logger.trace({ detectionData }, 'detectionData API data');

    deviceData = await getDevices(authenticatedRequest, requestWithDefaults, entity, options, Logger);
    Logger.trace({ deviceData }, 'devices API data');
    
    if (options.searchIoc) {
      //TODO: Add Query and data transformations
    }

    apiData = {
      devices: deviceData,
      detections: detectionData,
      statusCode: deviceData.statusCode === 200 && detectionData.statusCode === 200 ? 200 : detectionData.statusCode
    };

    return apiData;
  } catch (error) {
    const err = parseErrorToReadableJSON(error);
    Logger.error({ err }, 'error in getApiData');
    throw err;
  }
};

const buildResponse = async (authenticatedRequest, requestWithDefaults, entity, options, Logger) => {
  try {
    const apiData = await getApiData(authenticatedRequest, requestWithDefaults, entity, options, Logger);
    Logger.trace({ apiData }, 'api result');

    return apiData.statusCode === 200 || apiData.statusCode === 400
      ? polarityResponse(entity, apiData, Logger)
      : retryablePolarityResponse(entity);
  } catch (err) {
    const isConnectionTimeout = _.get(err, 'code', '') === 'ETIMEDOUT';
    const isConnectionReset = _.get(err, 'code', '') === 'ECONNRESET';
    if (isConnectionReset || isConnectionTimeout) return retryablePolarityResponse(entity, err);
    else throw polarityError(err);
  }
};

module.exports = buildResponse;
