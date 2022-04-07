const _ = require('lodash');

const polarityError = (err) => ({
  detail: err.message || 'Unknown Error',
  error: err
});

const emptyResponse = (entity) => ({
  entity,
  data: null
});

const polarityResponse = (entity, apiData, Logger) => {
  Logger.trace({ apiData }, 'API_DATE');
  if ((apiData && apiData.detections !== null) || (apiData && apiData.devices !== null)) {
    return {
      entity,
      data: {
        summary: getSummary(apiData),
        details: { detections: apiData.detections, devices: apiData.devices }
      }
    };
  } else {
    return emptyResponse(entity);
  }
};

const retryablePolarityResponse = (entity, err) => {
  return {
    entity,
    isVolatile: true,
    data: {
      summary: [err ? err.message : '! Lookup Limit Reached'],
      details: {
        summaryTag: err ? err.message : ['Lookup Limit Reached'],
        errorMessage: err
          ? err.message
          : 'A temporary Crowdstrike HX API search limit was reached. You can retry your search by pressing the "Retry Search" button.'
      }
    }
  };
};

const getSummary = (apiData) => {
  let tags = [];
  const { detections, devices } = apiData;

  if (apiData && apiData.detections !== null) {
    tags.push(`Detections: ${detections.length}`);
  }
  if (apiData && apiData.devices !== null) {
    tags.push(`Devices: ${devices.length}`);
  }

  return tags;
};

module.exports = {
  polarityError,
  emptyResponse,
  polarityResponse,
  retryablePolarityResponse
};
