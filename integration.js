const Bottleneck = require('bottleneck/es5');
const { map } = require('lodash/fp');
const buildResponse = require('./src/getApiData');
const { polarityError } = require('./src/responses');
const { containHost } = require('./src/containHost');
const { setRequestWithDefaults, authenticatedRequest } = require('./src/createRequestOptions');

let limiter = null;
let requestWithDefaults;
let Logger;

const startup = (logger) => {
  Logger = logger;
  requestWithDefaults = setRequestWithDefaults(Logger);
};

const _setupLimiter = (options) => {
  limiter = new Bottleneck({
    maxConcurrent: Number.parseInt(options.maxConcurrent, 10), // no more than 5 lookups can be running at single time
    highWater: 100, // no more than 100 lookups can be queued up
    strategy: Bottleneck.strategy.OVERFLOW,
    minTime: Number.parseInt(options.minTime, 10) // don't run lookups faster than 1 every 200 ms
  });
};

const doLookup = async (entities, options, callback) => {
  if (!limiter) _setupLimiter(options);

  try {
    const lookupResults = await Promise.all(
      map(
        async (entity) => await buildResponse(authenticatedRequest, requestWithDefaults, entity, options, Logger),
        entities
      )
    );

    Logger.trace({ lookupResults }, 'DoLookup Response');
    callback(null, lookupResults);
  } catch (err) {
    return callback(polarityError(err));
  }
};

const onMessage = async (payload, options, callback) => {
  const data = payload.data;

  switch (payload.action) {
    case 'CONTAIN_HOST':
      const containedHost = await containHost(authenticatedRequest, requestWithDefaults, data, options, Logger);
      return callback(null, containedHost);
    case 'RETRY_LOOKUP': {
      doLookup([payload.entity], options, (err, lookupResults) => {
        if (err) {
          Logger.error({ err }, 'Error retrying lookup');
          callback(err);
        } else {
          callback(
            null,
            lookupResults && lookupResults[0] && lookupResults[0].data === null
              ? { data: { summary: ['No Results Found on Retry'] } }
              : lookupResults[0]
          );
        }
      });
    }
    default:
      return;
  }
};

const validateStringOption = (errors, options, optionName, errMessage) => {
  if (
    typeof options[optionName].value !== 'string' ||
    (typeof options[optionName].value === 'string' && options[optionName].value.length === 0)
  ) {
    errors.push({
      key: optionName,
      message: errMessage
    });
  }
};

const validateTrailingSlash = (errors, options, optionName, errMessage) => {
  if (typeof options[optionName].value === 'string' && options[optionName].value.trim().endsWith('/')) {
    errors.push({
      key: optionName,
      message: errMessage
    });
  }
};

const validateOptions = (options, callback) => {
  let errors = [];

  validateStringOption(errors, options, 'url', 'You must provide the Crowdstrike API url.');
  validateTrailingSlash(errors, options, 'url', 'The url cannot end with a forward slash ("/").');
  validateStringOption(errors, options, 'id', 'You must provide a Client ID.');
  validateStringOption(errors, options, 'secret', 'You must provide a Client Secret.');

  callback(null, errors);
};

module.exports = {
  doLookup,
  onMessage,
  startup,
  validateOptions
};
