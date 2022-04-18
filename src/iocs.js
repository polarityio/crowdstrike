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

  if (!type) return { isValidType: true };

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
