const containHost = async (requestWithDefaults, token, entity, options, Logger) => {
  //will probably need
  const requestOptions = {
    method: 'POST',
    uri: `${options.url}/devices/entities/devices-actions/v2`,
    body: {
      ids: []
    }
  };
  const response = await requestWithDefaults(requestOptions);
};

module.exports = containHost;
