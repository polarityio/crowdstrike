const containHost = async (authenticatedRequest, requestWithDefaults, data, options, Logger) => {
  const status = data.status;
  const deviceId = data.id;

  try {
    if (status === 'normal' || status === 'contained') {
      const requestOptions = {
        method: 'POST',
        uri: `${options.url}/devices/entities/devices-actions/v2?action_name=${
          status === 'normal'
            ? 'contain'
            : 'lift_containment' || status === 'contained'
            ? 'lift_containment'
            : 'contained'
        }`,
        body: { ids: [deviceId] },
        json: true
      };

      Logger.trace({ requestOptions }, 'containHost requestOptions');
      const response = await authenticatedRequest(requestWithDefaults, requestOptions, options, Logger);
      return response;
    }
  } catch (err) {
    throw err;
  }
};

module.exports = { containHost };
