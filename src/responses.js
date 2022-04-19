const { flow, keys, some, size, get } = require('lodash/fp');

const polarityError = (err) => ({
  detail: err.message || 'Unknown Error',
  error: err
});

const emptyResponse = (entity) => ({
  entity,
  data: null
});

const polarityResponse = (entity, apiData, Logger) => {
  const someDataHasContent = flow(
    keys,
    some((dataKey) => {
      const data = get(dataKey, apiData);
      const content = get(
        get('contentKeyName', data), 
        data
      );
      return size(content);
    })
  )(apiData);

  return someDataHasContent
    ? {
        entity,
        data: {
          summary: getSummary(apiData, Logger),
          details: apiData
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
  
  const getPathSize = (path) => flow(get(path), size)(apiData)

  const detectionsSize = getPathSize('events.detections')
  if (detectionsSize) tags.push(`Detections: ${detectionsSize}`);

  const devicesSize = getPathSize('hosts.devices')
  if (devicesSize) tags.push(`Devices: ${devicesSize}`);

  const iocSize = getPathSize('iocs.indicators')
  if (iocSize) tags.push(`IOCs: ${iocSize}`);

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
