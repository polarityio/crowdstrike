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
  Logger.trace({ API_DATA_IN_RESPONSE: apiData });
  const { detections, devices } = apiData;
  return (apiData && apiData.detections !== null) || (apiData && apiData.devices !== null)
    ? {
        entity,
        data: {
          summary: getSummary(apiData, Logger),
          details: { detections, devices }
        }
      }
    : emptyResponse(entity);
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
          : 'A temporary CrowdStrike HX API search limit was reached. You can retry your search by pressing the "Retry Search" button.'
      }
    }
  };
};

const getSummary = (apiData, Logger) => {
  let tags = [];

  Logger.trace({ IN_SUMMARY: apiData.detections });
  if (apiData && apiData.detections !== null) {
    tags.push(`Detections: ${apiData.detections.length}`);
  }
  if (apiData && apiData.devices !== null) {
    tags.push(`Devices: ${apiData.devices.length}`);
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

// always show check status button
// See how containment buttons are rendered with multiple hosts.
// DESKTOP-G12Q1NU - belongs to Blair
