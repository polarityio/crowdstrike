const { get, size, flow, first, last, split, toUpper, getOr } = require('lodash/fp');

const getDevices = async (
  authenticatedRequest,
  requestWithDefaults,
  entity,
  options,
  Logger
) => {
  try {
    // this endpoint doesn't support domain lookups
    if (entity.isDomain) {
      return { devices: null, statusCode: 200 };
    }

    const deviceIds = await getDeviceIds(
      authenticatedRequest,
      requestWithDefaults,
      entity,
      options,
      Logger
    );
    if (!size(deviceIds)) return { devices: null, statusCode: 200 }; //handles the case of no data being found for an entity

    const requestOptions = {
      method: 'GET',
      uri: `${options.url}/devices/entities/devices/v1`,
      body: {
        ids: 111111
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
    Logger.trace({ response }, 'response in getDevices');

    const requestSuccessfulWithContent =
      get('statusCode', response) === 200 || get('body.resources.length', response) > 0;

    if (requestSuccessfulWithContent) {
      const devices = response.body.resources.map((resource) => {
        resource.__url = `https://falcon.crowdstrike.com/investigate/events/en-US/app/eam2/investigate__computer?aid_tok=${resource.device_id}&computer=*&customer_tok=*`;
        return resource;
      });

      Logger.trace(
        {
          devices,
          deviceTotalResults: size(deviceIds),
          statusCode: response.statusCode
        },
        'returned devices'
      );
      return {
        devices,
        contentKeyName: 'devices',
        deviceTotalResults: size(deviceIds),
        statusCode: response.statusCode
      };
    } else {
      return { devices: null, statusCode: response.statusCode };
    }
  } catch (error) {
    error.source = 'getDevices';
    throw error;
  }
};

const REQUEST_FILTER_BY_TYPE = {
  IPv4: (value) => `(external_ip:"${value}", local_ip:"${value}")`,
  hostname: (value) => `hostname:"${toUpper(value)}"`
};

const getDeviceIds = async (
  authenticatedRequest,
  requestWithDefaults,
  entity,
  options,
  Logger
) => {
  try {
    const entityWithType =
      entity.type === 'custom'
        ? flow(get('types'), first, split('.'), last)(entity)
        : entity.type;

    const requestFilter = getOr(
      () => {},
      entityWithType,
      REQUEST_FILTER_BY_TYPE
    )(entity.value);
    if (!requestFilter) return;

    const requestOptions = {
      method: 'GET',
      uri: `${options.url}/devices/queries/devices/v1`,
      qs: {
        filter: requestFilter
      },
      json: true
    };

    Logger.trace(
      { requestOptions, entityWithType, requestFilter },
      'searchIOCs request options'
    );

    const devicesIds = get(
      'body.resources',
      await authenticatedRequest(requestWithDefaults, requestOptions, options, Logger)
    );
    Logger.trace({ devicesIds }, 'Device Ids');
    return devicesIds;
  } catch (error) {
    error.source = 'getDeviceIds';
    throw error;
  }
};

const getAndUpdateDeviceState = async (
  authenticatedRequest,
  requestWithDefaults,
  deviceId,
  options,
  Logger
) => {
  try {
    const requestOptions = {
      method: 'GET',
      uri: `${options.url}/devices/entities/devices/v1`,
      body: {
        ids: [deviceId]
      },
      json: true
    };
    Logger.trace({ requestOptions }, 'request options in getAndUpdateDeviceState');

    const response = await authenticatedRequest(
      requestWithDefaults,
      requestOptions,
      options,
      Logger
    );
    Logger.trace({ response }, 'response in getAndUpdateDeviceState');

    const singleDeviceStatus = response.body.resources[0].status;
    Logger.trace({ singleDeviceStatus }, 'single device status');

    return singleDeviceStatus;
  } catch (error) {
    error.source = 'getAndUpdateDeviceState';
    throw error;
  }
};

module.exports = {
  getDevices,
  getAndUpdateDeviceState
};
