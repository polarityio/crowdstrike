const Bottleneck = require('bottleneck/es5');
const { map } = require('lodash/fp');
const buildResponse = require('./src/getApiData');
const { parseErrorToReadableJSON } = require('./src/responses');
const { containHost } = require('./src/containHost');
const { getAndUpdateDeviceState } = require('./src/devices');
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
    // CrowdStrike does not differentiate between a token with incorrect permissions and an expired token. As a result,
    // when a token expires, it is not possible to tell the difference between the two statuses.  If the token is expired
    // we need to refresh the token.  To ensure we can do this successfully when multiple entities are looked up in a
    // a single request we need to search the first entity and let the token refresh before running the rest of the
    // entities in parallel.  If we run all the entities in parallel then the counter which tries to track the number
    // auth attempts will get incremented by each failed lookup before the token can refresh and the user will see
    // an auth error even though the credentials are valid.
    const firstEntity = entities.shift();
    const firstResult = await buildResponse(authenticatedRequest, requestWithDefaults, firstEntity, options, Logger);

    const lookupResults = await Promise.all(
      map(
        async (entity) => await buildResponse(authenticatedRequest, requestWithDefaults, entity, options, Logger),
        entities
      )
    );

    lookupResults.push(firstResult);
    Logger.trace({ lookupResults }, 'DoLookup Response');
    callback(null, lookupResults);
  } catch (error) {

    const err = parseErrorToReadableJSON(error);
    Logger.error(err, 'doLookup Error');
    return callback(err);
  }
};

const onMessage = async (payload, options, callback) => {
  const data = payload.data;

  switch (payload.action) {
    case 'containOrUncontain':
      const containedHost = await containHost(authenticatedRequest, requestWithDefaults, data, options, Logger);
      return callback(null, containedHost);
    case 'getAndUpdateDeviceState':
      const deviceId = payload.data.id;

      const deviceStatus = await getAndUpdateDeviceState(
        authenticatedRequest,
        requestWithDefaults,
        deviceId,
        options,
        Logger
      );
      return callback(null, { deviceStatus });
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
