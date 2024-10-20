const authenticatedRequest = require('./authenticatedRequest');
const { getLogger } = require('./logger');

let cachedFalconScripts;
let cachedCustomScripts;
/**
 * Sample response from `queries/falcon-scripts`
 * ```
 * {
 *     "meta": {
 *         "query_time": 0.004516832,
 *         "pagination": {
 *             "offset": 0,
 *             "limit": 100,
 *             "total": 22
 *         },
 *         "powered_by": "empower-api",
 *         "trace_id": "9c019d4b-390c-4439-9bce-464848dfea0a"
 *     },
 *     "resources": [
 *         "d23f57ccdd344f3989eed207e307219f",
 *         "8bd32fb89f7c4a82a955966e699efcf5",
 *         "62c74994dd974792836b4dfd83b64158"
 *     ]
 *}
 * ```
 * @param entity
 * @param options
 * @returns {Promise<{detectionTotalResults: (*|number), contentKeyName: string, detections: (*), statusCode}>}
 */
const getFalconScripts = async (options) => {
  const Logger = getLogger();

  const getScriptIdOptions = {
    method: 'GET',
    uri: `${options.url}/real-time-response/queries/falcon-scripts/v1`,
    json: true
  };

  const scriptIdResponse = await authenticatedRequest(getScriptIdOptions, options);

  if (
    scriptIdResponse.body &&
    Array.isArray(scriptIdResponse.body.resources) &&
    scriptIdResponse.body.resources.length > 0
  ) {
    const getScriptContentOptions = {
      method: 'GET',
      uri: `${options.url}/real-time-response/entities/falcon-scripts/v1`,
      qs: {
        ids: scriptIdResponse.body.resources
      },
      useQuerystring: true,
      json: true
    };

    const scriptContentResponse = await authenticatedRequest(
      getScriptContentOptions,
      options
    );

    Logger.trace({ scriptContentResponse }, 'Response containing script content');

    return scriptContentResponse.body.resources;
  } else {
    // No Falcon Scripts available
    return [];
  }
};

/**
 * Sample response format:
 *
 * ```
 * {
 *     "meta": {
 *         "query_time": 0.064256471,
 *         "powered_by": "empower-api",
 *         "trace_id": "935fe774-7afd-4831-8c69-3fc3aedb894e"
 *     },
 *     "resources": [
 *         {
 *             "id": "462485bf7eea11efae5b9278d2476a52_18cf1db071734c858966bcc5452a49bd",
 *             "name": "Test Script",
 *             "description": "This is a test script just to see where this comes up in the REST API",
 *             "file_type": "script",
 *             "platform": [
 *                 "windows"
 *             ],
 *             "size": 1,
 *             "content": "\t",
 *             "created_by": "edorsey@threatconnect.com",
 *             "created_by_uuid": "18cf1db0-7173-4c85-8966-bcc5452a49bd",
 *             "created_timestamp": "2024-09-30T05:10:13.54503609Z",
 *             "modified_by": "edorsey@threatconnect.com",
 *             "modified_timestamp": "2024-09-30T05:12:32.199779093Z",
 *             "sha256": "2b4c342f5433ebe591a1da77e013d1b72475562d48578dca8b84bac6651c3cb9",
 *             "permission_type": "public",
 *             "run_attempt_count": 0,
 *             "run_success_count": 0,
 *             "write_access": true
 *         }
 *     ]
 * }
 * ```
 * @param options
 * @returns {Promise<{scripts: ([*]|[string]|[{detection_id: string}]|[{detection_id: string}]|[{detection_id: string}]|*)}>}
 */
const getCustomScripts = async (options) => {
  const Logger = getLogger();

  const requestOptions = {
    method: 'GET',
    uri: `${options.url}/real-time-response/entities/scripts/v1`,
    json: true
  };

  const { body } = await authenticatedRequest(requestOptions, options);

  Logger.trace({ body }, 'getCustomScripts');

  return body.resources;
};

const getRtrSession = async (deviceId, options) => {
  const Logger = getLogger();

  const requestOptions = {
    method: 'POST',
    uri: `${options.url}/real-time-response/entities/sessions/v1`,
    body: {
      device_id: deviceId,
      queue_offline: false
    },
    json: true
  };

  const { body } = await authenticatedRequest(requestOptions, options);
  let sessionId;
  if (
    Array.isArray(body.resources) &&
    body.resources.length > 0 &&
    body.resources[0].session_id
  ) {
    sessionId = body.resources[0].session_id;
    
    return {
      sessionId,
      pwd: body.resources[0].pwd
    };
  } else {
    Logger.error({ body }, 'getRtrSession invalid response body received');
    throw new Error('Unexpected response from getRtrSession.  Missing session_id field');
  }
};

/**
 * sample response from Run Script API endpoint
 *
 * ```
 * {
 *     "meta": {
 *         "query_time": 0.06820853,
 *         "powered_by": "empower-api",
 *         "trace_id": "fdfc8e69-f6c0-47b2-9737-6a9475795286"
 *     },
 *     "resources": [
 *         {
 *             "session_id": "645f1ca5-7d17-4089-963f-4111612b13b0",
 *             "cloud_request_id": "ceaec9d1-7ef7-4bda-aac0-84f47877a277",
 *             "queued_command_offline": false
 *         }
 *     ],
 *     "errors": null
 * }
 * ```
 *
 * @param sessionId
 * @param deviceId
 * @param baseCommand
 * @param commandString
 * @param options
 * @returns {Promise<void>} Returns the `cloud_request_id` which is required to poll for results
 */
const runScript = async (sessionId, deviceId, baseCommand, commandString, options) => {
  const Logger = getLogger();

  const requestOptions = {
    method: 'POST',
    uri: `${options.url}/real-time-response/entities/admin-command/v1`,
    body: {
      base_command: baseCommand,
      command_string: commandString,
      device_id: deviceId,
      persist: false,
      session_id: sessionId
    },
    json: true
  };

  const { body } = await authenticatedRequest(requestOptions, options);

  if (body.errors !== null) {
    // handle possible error
    Logger.error({ errors: body.errors }, 'Error encountered in runScript');
    throw new Error(
      'Unexpected response from runScript.  Missing cloud_request_id field'
    );
  } else if (
    Array.isArray(body.resources) &&
    body.resources.length > 0 &&
    body.resources[0].cloud_request_id
  ) {
    return body.resources[0].cloud_request_id;
  } else {
    // some other failure
    Logger.error({ body }, 'runScript invalid response body received');
    throw new Error(
      'Unexpected response from runScript.  Missing cloud_request_id field'
    );
  }
};

const maybeCacheRealTimeResponseScripts = async (options) => {
  if (options.enableRealTimeResponse && !cachedFalconScripts && !cachedCustomScripts) {
    cachedFalconScripts = await getFalconScripts(options);
    cachedCustomScripts = await getCustomScripts(options);
  }
};

const getCachedFalconScripts = () => {
  return cachedFalconScripts;
};

const getCachedCustomScripts = () => {
  return cachedCustomScripts;
};

const getRtrResult = async (cloudRequestId, sequenceId, options) => {
  const Logger = getLogger();

  const requestOptions = {
    method: 'GET',
    uri: `${options.url}/real-time-response/entities/admin-command/v1`,
    qs: {
      cloud_request_id: cloudRequestId,
      sequence_id: sequenceId
    },
    json: true
  };

  const { body } = await authenticatedRequest(requestOptions, options);

  if (Array.isArray(body.errors) && body.errors.length > 0) {
    // handle possible error
    Logger.error({ errors: body.errors }, 'Error encountered in runScript');
    throw new Error('Unexpected response from getRtrResult.');
  } else if (
    Array.isArray(body.resources) &&
    body.resources.length > 0 &&
    typeof body.resources[0].stdout === 'string' &&
    typeof body.resources[0].stderr === 'string' &&
    typeof body.resources[0].complete === 'boolean'
  ) {
    return {
      stdout: body.resources[0].stdout,
      stderr: body.resources[0].stderr,
      complete: body.resources[0].complete,
      sequenceId: body.resources[0].sequence_id
    };
  } else {
    // some other failure
    Logger.error({ body }, 'getRtrResult invalid response body received');
    throw new Error('Unexpected response from getRtrResult');
  }
};

const refreshRtrSession = async (options) => {};

const deleteRtrSession = async (sessionId, options) => {
  const Logger = getLogger();

  const requestOptions = {
    method: 'DELETE',
    uri: `${options.url}/real-time-response/entities/sessions/v1`,
    qs: {
      session_id: sessionId
    },
    json: true
  };

  // Returns a 204 on success with no content

  try {
    await authenticatedRequest(requestOptions, options);
  } catch (error) {
    // check for 400 in case the session was not found we want to just catch this
    //{
    //     "errors": [
    //         {
    //             "code": 400,
    //             "message": "Could not find existing session"
    //         }
    //     ]
    // }
    Logger.error(error, 'Error when deleting session');
    throw error;
  }
};

module.exports = {
  getFalconScripts,
  getCustomScripts,
  getRtrSession,
  runScript,
  refreshRtrSession,
  deleteRtrSession,
  getRtrResult,
  maybeCacheRealTimeResponseScripts,
  getCachedFalconScripts,
  getCachedCustomScripts
};
