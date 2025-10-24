const { flow, keys, some, size, get } = require('lodash/fp');
const { getLogger } = require('./logger');

const emptyResponse = (entity) => ({
  entity,
  data: null
});

const noResultsResponse = (entity) => ({
  entity,
  data: {
    summary: ['No results'],
    details: {
      noResults: true
    }
  }
});

/**
 * Generic error for REST requests
 */
class RequestError extends Error {
  constructor(message, status, description, requestOptions) {
    super(message);
    this.name = 'requestError';
    this.status = status;
    this.description = description;
    this.requestOptions = requestOptions;
    this.source = '';
    this.meta = null;
  }
}

/**
 * Thrown by generateAccessToken method if there is a failure to fetch a token
 */
class TokenRequestError extends Error {
  constructor(message, status, description, requestOptions) {
    super(message);
    this.name = 'tokenRequestError';
    this.status = status;
    this.description = description;
    this.requestOptions = requestOptions;
    this.source = '';
    this.meta = null;
  }
}

/**
 * Thrown by authenticated request method for any HTTP status codes where we want to allow
 * the user to retry their lookup.
 */
class RetryRequestError extends Error {
  constructor(message, status, description, requestOptions) {
    super(message);
    this.name = 'retryRequestError';
    this.status = status;
    this.description = description;
    this.requestOptions = requestOptions;
    this.source = '';
    this.meta = null;
  }
}

const polarityResponse = (entity, apiData, options) => {
  const Logger = getLogger();
  const someDataHasContent = flow(
    keys,
    some((dataKey) => {
      const data = get(dataKey, apiData);
      const content = get(get('contentKeyName', data), data);
      return size(content);
    })
  )(apiData);

  if (someDataHasContent) {
    return {
      entity,
      data: {
        summary: getSummary(apiData),
        details: apiData
      }
    };
  } else if (options.showNoResults) {
    return noResultsResponse(entity);
  } else {
    return emptyResponse(entity);
  }
};

const retryablePolarityResponse = (entity, err) => ({
  entity,
  isVolatile: true,
  data: {
    summary: [err ? err.message : '! Lookup Limit Reached'],
    details: {
      summaryTag: err ? err.message : ['Lookup Limit Reached'],
      status: err ? err.status : 'No Status',
      rateLimitLimit: err && err.meta ? err.meta.rateLimitLimit : null,
      rateLimitRemaining: err && err.meta ? err.meta.rateLimitRemaining : null,
      errorMessage: err
        ? err.message
        : 'A temporary CrowdStrike API search limit was reached. You can retry your search by pressing the "Retry Search" button.'
    }
  }
});

const getSummary = (apiData) => {
  const Logger = getLogger();
  let tags = [];

  const getPathSize = (path) => flow(get(path), size)(apiData);

  const detectionsSize = getPathSize('events.detections');
  if (detectionsSize) tags.push(`Detections: ${detectionsSize}`);

  const devicesSize = getPathSize('hosts.devices');
  if (devicesSize) tags.push(`Devices: ${devicesSize}`);

  const iocSize = getPathSize('iocs.indicators');
  if (iocSize) tags.push(`IOCs: ${iocSize}`);
  const vulnerabilitiesSize = getPathSize('vulnerabilities.resources');
  if (vulnerabilitiesSize) tags.push(`Vulnerabilities: ${vulnerabilitiesSize}`);

  return tags;
};

const parseErrorToReadableJSON = (err) => {
  return err instanceof Error
    ? {
        ...err,
        name: err.name,
        message: err.message,
        stack: err.stack,
        detail: err.message ? err.message : 'Unexpected error encountered'
      }
    : err;
};

module.exports = {
  emptyResponse,
  polarityResponse,
  retryablePolarityResponse,
  parseErrorToReadableJSON,
  RequestError,
  TokenRequestError,
  RetryRequestError
};
