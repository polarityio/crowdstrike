const { get, size } = require('lodash/fp');
const authenticatedRequest = require('./authenticatedRequest');
const { getLogger } = require('./logger');

const getIocIndicators = async (entity, options) => {
  const Logger = getLogger();
  try {
    if (entity.type === 'custom') {
      return { indicators: null, statusCode: 200 };
    }

    const indicatorIds = await getIndicatorIds(entity, options);
    if (!size(indicatorIds)) return { indicators: null, statusCode: 200 }; //handles the case of no data being found for an entity

    const requestOptions = {
      method: 'GET',
      uri: `${options.url}/iocs/entities/indicators/v1`,
      body: {
        ids: indicatorIds
      },
      json: true
    };
    Logger.trace({ requestOptions }, 'request options');

    const response = await authenticatedRequest(requestOptions, options);
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
    error.source = 'getIocIndicators';
    throw error;
  }
};

const getIndicatorIds = async (entity, options) => {
  const Logger = getLogger();
  try {
    const requestOptions = {
      method: 'GET',
      uri: `${options.url}/iocs/queries/indicators/v1`,
      qs: {
        filter: `(value: ~"${entity.value.toLowerCase()}")`
      },
      json: true
    };

    Logger.trace({ requestOptions }, 'searchIOCs request options');

    const indicatorIds = get(
      'body.resources',
      await authenticatedRequest(requestOptions, options)
    );
    Logger.trace({ indicatorIds }, 'Indicator Ids');
    return indicatorIds;
  } catch (error) {
    error.source = 'getIndicatorIds';
    throw error;
  }
};

const getIocDevicesIds = async (entity, options) => {
  const Logger = getLogger();
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
    const devicesIds = await authenticatedRequest(requestOptions, options);
    Logger.trace({ devicesIds }, 'Device Ids');
    return devicesIds;
  } catch (error) {
    error.source = 'getIocDevicesIds';
    throw error;
  }
};

module.exports = {
  getIocIndicators
};
