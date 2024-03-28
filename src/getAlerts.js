const { get, size } = require('lodash/fp');

const authenticatedRequest = require('./authenticatedRequest');
const { getLogger } = require('./logger');

const { SEVERITY_LEVELS_FOR_DETECTIONS } = require('./constants');

const getAlerts = async (entity, options) => {
  const Logger = getLogger();
  try {
    const alertIds = await searchForAlertIds(entity, options);
    if (Array.isArray(alertIds) && alertIds.length === 0) {
      // no detections found so just return
      return { detections: null, statusCode: 200 };
    }
    const requestOptions = {
      method: 'POST',
      uri: `${options.url}/alerts/entities/alerts/v2`,
      header: {
        'Content-Type': 'application/json'
      },
      body: {
        composite_ids: alertIds
      },
      json: true
    };

    Logger.trace({ requestOptions }, 'getAlerts request options');

    const response = await authenticatedRequest(requestOptions, options);
    Logger.trace({ response }, 'Response containing getAlerts');

    return {
      detections: get('body.resources', response),
      contentKeyName: 'detections',
      detectionTotalResults: size(alertIds),
      statusCode: response.statusCode
    };
  } catch (error) {
    error.source = 'getAlerts';
    throw error;
  }
};

const searchForAlertIds = async (entity, options) => {
  const Logger = getLogger();
  try {
    const filter = getFilter(options);
    const requestOptions = {
      method: 'GET',
      uri: `${options.url}/alerts/queries/alerts/v2`,
      qs: {
        q: entity.value.toLowerCase(),
        filter: filter,
        limit: 10
      },
      json: true
    };

    Logger.trace({ requestOptions }, 'searchForAlertIds request options');

    const alertIds = get(
      'body.resources',
      await authenticatedRequest(requestOptions, options)
    );
    Logger.trace({ alertIds, filter }, 'alertIds containing detection ids');

    return alertIds;
  } catch (error) {
    error.source = 'searchForAlertIds';
    throw error;
  }
};

const getFilter = (options) => {
  const statuses = options.detectionStatuses.reduce(
    (agg, status) => (status.value ? [...agg, `"${status.value}"`] : agg),
    []
  );

  let severityLevels = SEVERITY_LEVELS_FOR_DETECTIONS[options.minimumSeverity.value];

  let filter = `status:[${statuses.toString()}]+severity_name:[${severityLevels}]`;

  return filter;
};

module.exports = getAlerts;
