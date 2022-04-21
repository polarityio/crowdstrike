const { includes } = require('lodash');
const _ = require('lodash');
const { keys, every, get, flow } = require('lodash/fp');
const { getDetects } = require('./detects');
const { getDevices } = require('./devices');
const { getIocIndicators } = require('./iocs');
const {
  polarityResponse,
  polarityError,
  retryablePolarityResponse,
  parseErrorToReadableJSON
} = require('./responses');

const getApiData = async (
  authenticatedRequest,
  requestWithDefaults,
  entity,
  options,
  Logger
) => {
  try {

    const [detectionData, deviceData, iocData] = await Promise.all([
      getDetects(authenticatedRequest, requestWithDefaults, entity, options, Logger),
      getDevices(authenticatedRequest, requestWithDefaults, entity, options, Logger),
      options.searchIoc
        ? getIocIndicators(
            authenticatedRequest,
            requestWithDefaults,
            entity,
            options,
            Logger
          )
        : () => ({ indicators: null, statusCode: 400 })
    ]);
    Logger.trace({ detectionData, deviceData, iocData }, 'API data');
    
    const apiData = {
      hosts: deviceData,
      events: detectionData,
      iocs: iocData 
    };

    return apiData;
  } catch (error) {
    const err = parseErrorToReadableJSON(error);
    Logger.error({ err }, 'error in getApiData');
    throw err;
  }
};

const buildResponse = async (
  authenticatedRequest,
  requestWithDefaults,
  entity,
  options,
  Logger
) => {
  try {
    const apiData = await getApiData(
      authenticatedRequest,
      requestWithDefaults,
      entity,
      options,
      Logger
    );
    Logger.trace({ apiData }, 'api result');

    const allStatusCodesAreSuccessful = flow(
      keys,
      every((dataKey) => [200, 400].includes(get([dataKey, 'statusCode'], apiData)))
    )(apiData);

    return allStatusCodesAreSuccessful
      ? polarityResponse(entity, apiData, Logger)
      : retryablePolarityResponse(entity);
  } catch (err) {
    const isConnectionTimeout = _.get(err, 'code', '') === 'ETIMEDOUT';
    const isConnectionReset = _.get(err, 'code', '') === 'ECONNRESET';
    if (isConnectionReset || isConnectionTimeout)
      return retryablePolarityResponse(entity, err);
    else throw polarityError(err);
  }
};

module.exports = buildResponse;
