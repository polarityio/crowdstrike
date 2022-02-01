const SEVERITY_LEVELS = {
  Critical: '"Critical"',
  High: '"High","Critical"',
  Medium: '"Medium","High","Critical"',
  Low: '"Low","Medium","High","Critical"'
};

/* 
  getDetects returns devices that were matched with returned id's from searchDetects(). 
  It is possible that searchDetects returns a list of ids that do not have a matching device 
*/
const searchDetects = async (authenticatedRequest, requestWithDefaults, entity, options, Logger) => {
  try {
    const requestOptions = {
      method: 'GET',
      uri: `${options.url}/detects/queries/detects/v1`,
      qs: _getQuery(entity, options),
      json: true
    };

    Logger.trace({ requestOptions }, 'searchDetects() request options');

    const response = await authenticatedRequest(requestWithDefaults, requestOptions, options, Logger);
    Logger.trace({ response }, 'Response containing detection ids');

    return response;
  } catch (err) {
    throw err;
  }
};

// ONLY CALL THIS IF IDS ARE RETURNED
const getDetects = async (authenticatedRequest, requestWithDefaults, entity, options, Logger) => {
  try {
    const detectsResponse = await searchDetects(authenticatedRequest, requestWithDefaults, entity, options, Logger);
    const detectIds = detectsResponse.body.resources;

    Logger.trace({ detectIds }, 'detections ids');

    if (detectIds.length) {
      //TEMPORARY CHECK
      const requestOptions = {
        method: 'POST',
        uri: `${options.url}/detects/entities/summaries/GET/v1`,
        body: {
          ids: detectIds
        },
        json: true
      };
      Logger.trace({ requestOptions }, 'getDetects() request options');

      const response = await authenticatedRequest(requestWithDefaults, requestOptions, options, Logger);
      Logger.trace({ response }, 'Response from detects');

      const foundDetects = response.body.resources.map((resource) => {
        let split = resource.detection_id.split(':');
        resource.__url = `https://falcon.crowdstrike.com/activity/detections/detail/${split[1]}/${split[2]}`;
        return resource;
      });

      Logger.debug({ foundDetects }, 'getDetects() return result');
      return foundDetects
    }
  } catch (err) {
    throw err;
  }
};

const _getQuery = (entityObj, options) => {
  const statuses = options.detectionStatuses.reduce((accum, statusObj) => {
    // statuses need to be in double quotes
    if (statusObj && statusObj.value) {
      accum.push(`"${statusObj.value}"`);
    }
    return accum;
  }, []);

  let severityLevels = SEVERITY_LEVELS[options.minimumSeverity.value];

  let type = 'sha256';

  if (entityObj.isMD5) {
    type = 'md5';
  } else if (entityObj.type === 'custom' && entityObj.types.indexOf('custom.exeFile') >= 0) {
    type = 'filename';
  }

  let filter = `+status:[${statuses.toString()}]+max_severity_displayname:[${severityLevels}]`;

  if (entityObj.isIPv4) {
    return {
      limit: 10,
      filter: `(device.external_ip:"${entityObj.value}"${filter}),(device.local_ip:"${entityObj.value}"${filter})`
    };
  } else {
    return {
      limit: 10,
      filter: `(q:"${entityObj.value.toLowerCase()}"${filter}),(behaviors.${type}:"${entityObj.value.toLowerCase()}"${filter})`
    };
  }
};

module.exports = {
  searchDetects,
  getDetects
};
