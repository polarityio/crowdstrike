const { parseErrorToReadableJSON } = require('./responses');
const { get } = require('lodash/fp');

const getDevices = async (authenticatedRequest, requestWithDefaults, entity, options, Logger) => {
  try {
    const ids = await getIocIds(authenticatedRequest, requestWithDefaults, entity, options, Logger);
    const deviceIds = ids.body.resources;
    Logger.trace({ ids: ids.body.meta.pagination }, 'device ids');
    /// in ids - ids.body.meta.pagination.limit

    const requestOptions = {
      method: 'GET',
      uri: `${options.url}/devices/entities/devices/v1`,
      body: {
        ids: deviceIds
      },
      json: true
    };
    Logger.trace({ requestOptions }, 'request options');

    const response = await authenticatedRequest(requestWithDefaults, requestOptions, options, Logger);
    Logger.trace({ response }, 'response in getDevices');

    if (get('statusCode', response) === 200 || get('body.resources.length', response) > 0) {
      const devices = response.body.resources.map((resource) => {
        resource.__url = `https://falcon.crowdstrike.com/investigate/events/en-US/app/eam2/investigate__computer?aid_tok=${resource.device_id}&computer=*&customer_tok=*`;
        return resource;
      });

      Logger.trace(
        { devices, deviceTotalResults: ids.body.meta.pagination.limit, statusCode: response.statusCode },
        'returned devices'
      );
      return { devices, deviceTotalResults: ids.body.meta.pagination.limit, statusCode: response.statusCode };
    } else {
      return { devices: null, statusCode: response.statusCode };
    }
  } catch (error) {
    const err = parseErrorToReadableJSON(error);
    Logger.error({ err }, 'error in getDevices');
    throw err;
  }
};

const getIocIds = async (authenticatedRequest, requestWithDefaults, entity, options, Logger) => {
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

  if (!type) return;

  requestOptions.qs = { type, value: entity.value };

  Logger.trace({ requestOptions }, 'searchIOCs request options');

  try {
    const devicesIds = await authenticatedRequest(requestWithDefaults, requestOptions, options, Logger);
    Logger.trace({ devicesIds }, 'Device Ids');
    return devicesIds;
  } catch (error) {
    const err = parseErrorToReadableJSON(error);
    Logger.error({ err }, 'error in getIocIds');
    throw err;
  }
};

const getAndUpdateDeviceState = async (authenticatedRequest, requestWithDefaults, deviceId, options, Logger) => {
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

    const response = await authenticatedRequest(requestWithDefaults, requestOptions, options, Logger);
    Logger.trace({ response }, 'response in getAndUpdateDeviceState');

    const singleDeviceStatus = response.body.resources[0].status;
    Logger.trace({ singleDeviceStatus }, 'single device status');

    return singleDeviceStatus;
  } catch (error) {
    const err = parseErrorToReadableJSON(error);
    Logger.error({ err }, 'error in getAndUpdateDeviceState');
    throw err;
  }
};

module.exports = {
  getDevices,
  getIocIds,
  getAndUpdateDeviceState
};
