const _ = require('lodash');

const polarityError = (err) => ({
  detail: err.message || 'Unknown Error',
  error: err
});

const emptyResponse = (entity) => ({
  entity,
  data: null
});

const polarityResponse = (entity, response, Logger) => {
  Logger.trace({ detects: response });
  return response.length
    ? [
        {
          entity,
          data: response.length ? { summary: getSummary(response), details: response } : null
        }
      ]
    : emptyResponse(entity);
};

const retryablePolarityResponse = (entity) => ({
  entity,
  isVolatile: true,
  data: {
    summary: ['Lookup limit reached'],
    details: {
      summaryTag: 'Lookup limit reached',
      errorMessage:
        'A temporary FireEye HX API search limit was reached. You can retry your search by pressing the "Retry Search" button.'
    }
  }
});

const getSummary = (response) => {
  // let tags = [];
  // tags.push(`Alerts: ${response.alerts.entries.length}`);
  // for (const alert of response.alerts.entries) {
  //   tags.push(`IOC: ${alert.indicator.name}`);
  // }
  // return _.uniq(tags);
};

module.exports = {
  polarityError,
  emptyResponse,
  polarityResponse,
  retryablePolarityResponse
};
