const _ = require('lodash');
const getAlerts = require('./getAlerts');
const { getDeviceIds, getDeviceById } = require('./devices');
const getIocIndicators = require('./iocs');
const {
  polarityResponse,
  retryablePolarityResponse,
  RetryRequestError
} = require('./responses');
const { getLogger } = require('./logger');
const { getCachedFalconScripts, getCachedCustomScripts } = require('./realTimeResponse');
const { getVulnerabilityByCve } = require('./getVulnerabilityByCve');

const getApiData = async (entity, options) => {
  const Logger = getLogger();
  try {
    let deviceData;
    let alertData = { alerts: null, statusCode: 400 };
    let iocData = { indicators: null, statusCode: 400 };
    let vulnerabilityData = { vulnerabilities: null, statusCode: 400 };

    if (entity.type === 'cve') {
      vulnerabilityData = await getVulnerabilityByCve(entity.value, options);
      Logger.trace({ vulnerabilityData }, 'Vulnerability API data');

      if (vulnerabilityData && vulnerabilityData.vulnerabilities.length > 0) {
        const aids = vulnerabilityData.vulnerabilities.map((vuln) => vuln.aid);
        const uniqueAids = [...new Set(aids)];
        deviceData = await getDeviceById(uniqueAids, options);
        Logger.trace({ deviceData }, 'Device data for CVE');
      }
    } else {
      alertData = await getAlerts(entity, options);
      Logger.trace({ alertData }, 'alertData API data');

      const deviceIds = await getDeviceIds(entity, options);
      deviceData = await getDeviceById(deviceIds, options);
      Logger.trace({ deviceData }, 'devices API data');

      if (options.searchIoc) {
        iocData = await getIocIndicators(entity, options);
        Logger.trace({ iocData }, 'IOC API data');
      }
    }

    return {
      hosts: deviceData,
      events: alertData,
      iocs: iocData,
      vulnerabilities: vulnerabilityData,
      // Send empty array for scripts until user connects to a host
      falconScripts: [],
      customScripts: []
    };
  } catch (error) {
    throw error;
  }
};

const buildResponse = async (entity, options) => {
  const Logger = getLogger();
  try {
    const apiData = await getApiData(entity, options);
    Logger.trace({ apiData }, 'api result');
    return polarityResponse(entity, apiData, options);
  } catch (err) {
    if (err instanceof RetryRequestError) {
      return retryablePolarityResponse(entity, err);
    } else {
      throw err;
    }
  }
};

module.exports = buildResponse;
