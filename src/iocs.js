const { parseErrorToReadableJSON } = require('./responses');
const { get, size, toLower } = require('lodash/fp');
const { SEVERITY_LEVELS_FOR_INDICATORS } = require('./constants');

const getIocIndicators = async (
  authenticatedRequest,
  requestWithDefaults,
  entity,
  options,
  Logger
) => {
  try {
    const indicatorIds = await getIndicatorIds(
      authenticatedRequest,
      requestWithDefaults,
      entity,
      options,
      Logger
    );
    if (!size(indicatorIds)) return { indicators: null, statusCode: 400 }; //handles the case of no data being found for an entity

    const requestOptions = {
      method: 'GET',
      uri: `${options.url}/iocs/entities/indicators/v1`,
      body: {
        ids: indicatorIds
      },
      json: true
    };
    Logger.trace({ requestOptions }, 'request options');

    const response = await authenticatedRequest(
      requestWithDefaults,
      requestOptions,
      options,
      Logger
    );
    Logger.trace({ response }, 'response in getIocIndicators');

    const requestSuccessfulWithContent =
      get('statusCode', response) === 200 || get('body.resources.length', response) > 0;

    if (requestSuccessfulWithContent) {
      const indicators = response.body.resources.map((resource) => {
        resource.__url = `https://falcon.crowdstrike.com/iocs/indicators/${resource.id}`;
        return resource;
      });

      Logger.trace(
        {
          indicators,
          indicatorsTotalResults: size(indicatorIds),
          statusCode: response.statusCode
        },
        'returned indicators'
      );
      return {
        indicators,
        contentKeyName: 'indicators',
        indicatorsTotalResults: size(indicatorIds),
        statusCode: response.statusCode
      };
    } else {
      return { indicators: null, statusCode: response.statusCode };
    }
  } catch (error) {
    const err = parseErrorToReadableJSON(error);
    Logger.error({ err }, 'error in getIocIndicators');
    throw err;
  }
};

const getIndicatorIds = async (
  authenticatedRequest,
  requestWithDefaults,
  entity,
  options,
  Logger
) => {
  try {
    const requestOptions = {
      method: 'GET',
      uri: `${options.url}/iocs/queries/indicators/v1`,
      qs: {
        filter:
          `(value: ~"${entity.value}", description: ~"${entity.value}",` +
          `metadata.filename.raw: "${entity.value}", metadata.original_filename.raw: "${entity.value}", value: ~"${toLower(entity.value)}")` +
          `+severity:[${SEVERITY_LEVELS_FOR_INDICATORS[options.minimumSeverity.value]}]`
      },
      json: true
    };

    Logger.trace({ requestOptions }, 'searchIOCs request options');

    const indicatorIds = get(
      'body.resources',
      await authenticatedRequest(requestWithDefaults, requestOptions, options, Logger)
    );
    Logger.trace({ indicatorIds }, 'Indicator Ids');
    return indicatorIds;
  } catch (error) {
    const err = parseErrorToReadableJSON(error);
    Logger.error({ err }, 'error in getIndicatorIds');
    throw err;
  }
};

const getIocDevicesIds = async (
  authenticatedRequest,
  requestWithDefaults,
  entity,
  options,
  Logger
) => {
  const requestOptions = {
    method: 'GET',
    uri: `${options.url}/indicators/queries/devices/v1`,
    json: true
  };

  const type = entity.isMD5
    ? 'md5'
    : entity.isSHA256
    ? 'sha256'
    : entity.isIPv4
    ? 'ipv4'
    : entity.isIPv6
    ? 'ipv6'
    : entity.isDomain
    ? 'domain'
    : false;

  if (!type) return { isValidType: true };

  requestOptions.qs = { type, value: entity.value };

  Logger.trace({ requestOptions }, 'searchIOCs request options');

  try {
    const devicesIds = await authenticatedRequest(
      requestWithDefaults,
      requestOptions,
      options,
      Logger
    );
    Logger.trace({ devicesIds }, 'Device Ids');
    return devicesIds;
  } catch (error) {
    const err = parseErrorToReadableJSON(error);
    Logger.error({ err }, 'error in getIocIds');
    throw err;
  }
};

module.exports = {
  getIocIndicators
};
