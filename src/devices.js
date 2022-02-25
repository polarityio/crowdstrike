const getDevices = async (authenticatedRequest, requestWithDefaults, entity, options, Logger) => {
  try {
    const ids = await getIocIds(authenticatedRequest, requestWithDefaults, entity, options, Logger);
    const deviceIds = ids.body.resources;

    Logger.trace({ deviceIds }, 'device ids');

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

    const devices = response.body.resources.map((resource) => {
      resource.__url = `https://falcon.crowdstrike.com/investigate/events/en-US/app/eam2/investigate__computer?aid_tok=${resource.device_id}&computer=*&customer_tok=*`;
      return resource;
    });

    Logger.trace({ devices, statusCode: response.statusCode }, 'returned devices');
    return { devices, statusCode: response.statusCode };
  } catch (err) {
    throw err;
  }
};

const getIocIds = async (authenticatedRequest, requestWithDefaults, entity, options, Logger) => {
  const requestOptions = {
    method: 'GET',
    uri: `${options.url}/indicators/queries/devices/v1`,
    json: true
  };

  if (entity.isMD5) {
    requestOptions.qs = { type: 'md5', value: entity.value };
  } else if (entity.isSHA256) {
    requestOptions.qs = { type: 'sha256', value: entity.value };
  } else if (entity.isIPv4) {
    requestOptions.qs = { type: 'ipv4', value: entity.value };
  } else if (entity.isIPv6) {
    requestOptions.qs = { type: 'ipv6', value: entity.value };
  } else if (entity.isDomain) {
    requestOptions.qs = { type: 'domain', value: entity.value };
  } else {
    return;
  }

  Logger.trace({ requestOptions }, 'searchIOCs request options');

  try {
    const devicesIds = await authenticatedRequest(requestWithDefaults, requestOptions, options, Logger);
    Logger.trace({ devicesIds }, 'Device Ids');
    return devicesIds;
  } catch (err) {
    throw err;
  }
};

module.exports = {
  getDevices,
  getIocIds
};
