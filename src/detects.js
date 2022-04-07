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
const getDetectionIds = async (authenticatedRequest, requestWithDefaults, entity, options, Logger) => {
  try {
    const requestOptions = {
      method: 'GET',
      uri: `${options.url}/detects/queries/detects/v1`,
      qs: _getQuery(entity, options, Logger),
      json: true
    };

    Logger.trace({ requestOptions }, 'searchDetects request options');

    const response = await authenticatedRequest(requestWithDefaults, requestOptions, options, Logger);
    Logger.trace({ response }, 'Response containing detection ids');

    return response;
  } catch (err) {
    throw err;
  }
};

const getDetects = async (authenticatedRequest, requestWithDefaults, entity, options, Logger) => {
  try {
    const detectionIdsResponse = await getDetectionIds(
      authenticatedRequest,
      requestWithDefaults,
      entity,
      options,
      Logger
    );

    Logger.trace({ detectionIdsResponse }, 'detections');
    const ids = detectionIdsResponse.body.resources;

    const requestOptions = {
      method: 'POST',
      uri: `${options.url}/detects/entities/summaries/GET/v1`,
      body: {
        ids
      },
      json: true
    };

    Logger.trace({ requestOptions }, 'getDetects request options');

    const response = await authenticatedRequest(requestWithDefaults, requestOptions, options, Logger);
    Logger.trace({ response }, 'Response from detects');

    if (
      (response && response.statusCode === 200) ||
      (response && response.body && response.body.resources && response.body.resources.length > 0)
    ) {
      const detections = response.body.resources.map((resource) => {
        let split = resource.detection_id.split(':');
        resource.__url = `https://falcon.crowdstrike.com/activity/detections/detail/${split[1]}/${split[2]}`;
        return resource;
      });

      Logger.trace({ detections }, 'getDetects return result');
      return { detections, statusCode: response.statusCode };
    } else {
      return { detections: null, statusCode: response.statusCode };
    }
  } catch (err) {
    throw err;
  }
};

const _getQuery = (entityObj, options, Logger) => {
  const statuses = options.detectionStatuses.reduce((accum, statusObj) => {
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

  if (entityObj.type === 'custom' && entityObj.types.indexOf('custom.hostname') >= 0) {
    type = 'hostname';
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
  getDetects
};
