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
  const { detections, devices } = apiData;
  return (apiData && apiData.detections.detections !== null) || (apiData && apiData.devices.devices !== null)
    ? {
        entity,
        data: {
          summary: getSummary(apiData, Logger),
          details: { detections, devices }
        }
      }
    : emptyResponse(entity);
};

const retryablePolarityResponse = (entity, err) => ({
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
});

const getSummary = (apiData, Logger) => {
  let tags = [];
  
  if (apiData && apiData.detections.detections !== null) {
    tags.push(`Detections: ${apiData.detections.detections.length}`);
  }
  if (apiData && apiData.devices.devices !== null) {
    tags.push(`Devices: ${apiData.devices.devices.length}`);
  }

  return tags;
};

const parseErrorToReadableJSON = (error) => {
  return JSON.parse(JSON.stringify(error, Object.getOwnPropertyNames(error)));
};

module.exports = {
  polarityError,
  emptyResponse,
  polarityResponse,
  retryablePolarityResponse,
  parseErrorToReadableJSON
};
