const _ = require('lodash');
const { getDetects } = require('./detects');
const { getDevices } = require('./devices');
const { polarityResponse, polarityError, retryablePolarityResponse } = require('./responses');

const getApiData = async (authenticatedRequest, requestWithDefaults, entity, options, Logger) => {
  let deviceResponse;
  try {
    const detectionResponse = await getDetects(authenticatedRequest, requestWithDefaults, entity, options, Logger);
    Logger.trace({ detectionResponse }, 'detectionResponse API data');

    if (options.searchIoc) {
      deviceResponse = await getDevices(authenticatedRequest, requestWithDefaults, entity, options, Logger);
      Logger.trace({ deviceResponse }, 'devices API data');
    }

    apiData = {
      devices: deviceResponse.devices,
      detections: detectionResponse.detections,
      statusCode:
        deviceResponse.statusCode === 200 && detectionResponse.statusCode === 200 ? 200 : detectionResponse.statusCode
    };

    return apiData;
  } catch (err) {
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
