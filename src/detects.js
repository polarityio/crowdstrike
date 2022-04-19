const { parseErrorToReadableJSON } = require('./responses');
const { get } = require('lodash/fp');
const { SEVERITY_LEVELS_FOR_DETECTIONS } = require('./constants');

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
  } catch (error) {
    const err = parseErrorToReadableJSON(error);
    Logger.error({ err }, 'error in getAndUpdateDeviceState');
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

    if (get('statusCode', response) === 200 || get('body.resources.length', response) > 0) {
      const detections = response.body.resources.map((resource) => {
        let split = resource.detection_id.split(':');
        resource.__url = `${options.url}/activity/detections/detail/${split[1]}/${split[2]}`;
        return resource;
      });

      Logger.trace({ detections }, 'getDetects return result');
      return {
        detections,
        contentKeyName: 'detections',
        detectionTotalResults: detectionIdsResponse.body.meta.pagination.total,
        statusCode: response.statusCode
      };
    } else {
      return { detections: null, statusCode: response.statusCode };
    }
  } catch (error) {
    const err = parseErrorToReadableJSON(error);
    Logger.error({ err }, 'error in getAndUpdateDeviceState');
    throw err;
  }
};

const _getQuery = (entityObj, options) => {
  const statuses = options.detectionStatuses.reduce((accum, statusObj) => {
    if (statusObj && statusObj.value) {
      accum.push(`"${statusObj.value}"`);
    }
    return accum;
  }, []);

  let severityLevels = SEVERITY_LEVELS_FOR_DETECTIONS[options.minimumSeverity.value];

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
  } else if (entityObj.type === 'custom' && entityObj.types.indexOf('custom.hostname') >= 0){
    return {
      limit: 10,
      filter: `device.hostname: "${entityObj.value.toUpperCase()}"`
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
