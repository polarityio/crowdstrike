const { getAndUpdateDeviceState } = require('./devices');
const authenticatedRequest = require('./authenticatedRequest');
const { getLogger } = require('./logger');

const containHost = async (data, options) => {
  const Logger = getLogger();
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

      const response = await authenticatedRequest(requestOptions, options, Logger);
      Logger.trace({ response }, 'devices response');

      const updatedDeviceState = await getAndUpdateDeviceState(deviceId, options, Logger);

      Logger.trace({ updatedDeviceState }, 'single device response');
      return { response, updatedDeviceState };
    }
  } catch (err) {
    err.source = 'containHost';
    throw err;
  }
};

module.exports = { containHost };
