const Bottleneck = require('bottleneck/es5');
const { map } = require('lodash/fp');
const buildResponse = require('./src/getApiData');
const { parseErrorToReadableJSON } = require('./src/responses');
const { containHost } = require('./src/containHost');
const { getAndUpdateDeviceState } = require('./src/devices');
const { setLogger } = require('./src/logger');
const { logToken } = require('./src/tokenCache');
const {
  maybeCacheRealTimeResponseScripts,
  getRtrSession,
  deleteRtrSession,
  runScript,
  getRtrResult,
  getCachedFalconScripts,
  getCachedCustomScripts
} = require('./src/realTimeResponse');

let limiter = null;
let Logger;

const startup = (logger) => {
  Logger = logger;
  setLogger(Logger);
};

const _setupLimiter = (options) => {
  limiter = new Bottleneck({
    maxConcurrent: Number.parseInt(options.maxConcurrent, 10), // no more than 5 lookups can be running at single time
    highWater: 100, // no more than 100 lookups can be queued up
    strategy: Bottleneck.strategy.OVERFLOW,
    minTime: Number.parseInt(options.minTime, 10) // don't run lookups faster than 1 every 200 ms
  });
};

const doLookup = async (entities, options, callback) => {
  if (!limiter) _setupLimiter(options);

  Logger.trace({ entities, options }, 'doLookup');

  try {
    await maybeCacheRealTimeResponseScripts(options);
    const lookupResults = await Promise.all(
      map(async (entity) => await buildResponse(entity, options), entities)
    );
    Logger.trace({ lookupResults }, 'DoLookup Response');
    logToken(options);
    callback(null, lookupResults);
  } catch (error) {
    const err = parseErrorToReadableJSON(error);
    Logger.error(err, 'doLookup Error');
    return callback(err);
  }
};

const falconScriptRegex = /falconscript -Name="(.+?)"/i;
const customScriptRegex = /runscript -CloudFile="(.+?)"/i;

/**
 * Checks to see if the provided `commandString` is an enabled command (based on the integration settings)
 *
 * @param commandString the command the user is trying to run
 * @param options user options
 * @returns {*|boolean} true if the command is enabled, false is not
 */
const isEnabledScriptOrCommand = (commandString, options) => {
  // Only enabled scripts are cached
  const cachedFalconScripts = getCachedFalconScripts().map((script) => script.name);
  const cachedCustomScripts = getCachedCustomScripts().map((script) => script.name);
  const supportedCommands = options.enabledCommands
    .split(',')
    .map((command) => command.trim().toLowerCase());

  const commandTokens = commandString.split(' ').map((token) => token.trim());

  if (commandTokens.length === 0) {
    return false;
  }

  const command = commandTokens[0];

  Logger.trace(
    {
      commandString,
      commandTokens,
      supportedCommands,
      command,
      cachedCustomScripts,
      cachedFalconScripts
    },
    'isEnabledScriptOrCommand'
  );

  if (command === 'falconscript') {
    // Falcon scripts are in this format:
    // falconscript -Name="LocalUser" -JsonInput=```''```
    const matches = falconScriptRegex.exec(commandString);
    if (matches && matches.length >= 2) {
      return cachedFalconScripts.includes(matches[1]);
    } else {
      return false;
    }
  } else if (command === 'runscript') {
    // Custom scripts are in this format:
    // runscript -CloudFile="Custom Process Script"  -CommandLine=""
    const matches = customScriptRegex.exec(commandString);
    if (matches && matches.length >= 2) {
      return cachedCustomScripts.includes(matches[1]);
    } else {
      return false;
    }
  } else {
    // this is a command (versus a script)
    return supportedCommands.includes(command);
  }
};

const onMessage = async (payload, options, callback) => {
  const data = payload.data;

  // Possibly required if the integration was restarted but a user already had
  // a result in their overlay window and run an action that causes an `onMessage`
  // request.
  await maybeCacheRealTimeResponseScripts(options);

  switch (payload.action) {
    case 'GET_RTR_SESSION':
      try {
        if (!options.enableRealTimeResponse) {
          callback({
            detail: 'Real Time Response is disabled',
            status: 401
          });
          return;
        }

        const { deviceId, platform } = payload;
        const { sessionId, pwd } = await getRtrSession(deviceId, options);

        // Only send back scripts that are for the supported platform
        const falconScripts = getCachedFalconScripts().filter((script) =>
          Array.isArray(script.platform)
            ? script.platform.includes(platform.toLowerCase())
            : script.platform.toLowerCase() === platform.toLowerCase()
        );
        const customScripts = getCachedCustomScripts().filter((script) =>
          Array.isArray(script.platform)
            ? script.platform.includes(platform.toLowerCase())
            : script.platform.toLowerCase() === platform.toLowerCase()
        );
        Logger.trace({ sessionId }, 'Retrieved RTR Session Id');
        callback(null, {
          sessionId,
          pwd,
          falconScripts,
          customScripts
        });
      } catch (error) {
        Logger.error({ error }, 'onMessage GET_RTR_SESSION Error');
        if(error.meta && Array.isArray(error.meta.errors) && error.meta.errors.length > 0){
          error.detail = `${error.meta.errors[0].message} (Code: ${error.meta.errors[0].code})`;
        }
        callback(error);
      }
      break;
    case 'DELETE_RTR_SESSION':
      try {
        if (!options.enableRealTimeResponse) {
          callback({
            detail: 'Real Time Response is disabled',
            status: 401
          });
          return;
        }

        const { sessionId } = payload;
        await deleteRtrSession(sessionId, options);
        callback(null, {
          disconnected: true
        });
      } catch (error) {
        // specifically look for a session timeout error
        if (!handleExpiredRtrSession(error, callback)) {
          Logger.error({ error }, 'onMessage DELETE_RTR_SESSION Error');
          if(error.meta && Array.isArray(error.meta.errors) && error.meta.errors.length > 0){
            error.detail = `${error.meta.errors[0].message} (Code: ${error.meta.errors[0].code})`;
          }
          callback(error);
        }
      }
      break;
    case 'RUN_SCRIPT':
      try {
        if (!options.enableRealTimeResponse) {
          callback({
            detail: 'Real Time Response is disabled',
            status: 401
          });
          return;
        }

        const { sessionId, deviceId, baseCommand, commandString } = payload;

        if (!isEnabledScriptOrCommand(commandString, options)) {
          callback(null, {
            unsupportedScriptOrCommand: true
          });
          return;
        }

        const cloudRequestId = await runScript(
          sessionId,
          deviceId,
          baseCommand,
          commandString,
          options
        );

        Logger.trace({ cloudRequestId }, 'Retrieved cloudRequestId from RUN_SCRIPT');

        callback(null, {
          expiredSession: false,
          cloudRequestId
        });
      } catch (error) {
        // specifically look for a session timeout error
        if (!handleExpiredRtrSession(error, callback)) {
          Logger.error({ error }, 'onMessage RUN_SCRIPT Error');
          if(error.meta && Array.isArray(error.meta.errors) && error.meta.errors.length > 0){
            error.detail = `${error.meta.errors[0].message} (Code: ${error.meta.errors[0].code})`;
          }
          callback(error);
        }
      }
      break;
    case 'GET_RTR_RESULT':
      try {
        if (!options.enableRealTimeResponse) {
          callback({
            detail: 'Real Time Response is disabled',
            status: 401
          });
          return;
        }

        const { cloudRequestId, sequenceId } = payload;
        const {
          stdout,
          stderr,
          complete,
          sequenceId: responseSequenceId
        } = await getRtrResult(cloudRequestId, sequenceId, options);
        Logger.trace(
          { stdout, stderr, complete },
          'Retrieved result from GET_RTR_RESULT'
        );
        callback(null, {
          stdout,
          stderr,
          complete,
          sequenceId: responseSequenceId
        });
      } catch (error) {
        // specifically look for a session timeout error
        if (!handleExpiredRtrSession(error, callback)) {
          Logger.error({ error }, 'onMessage GET_RTR_RESULT Error');
          if(error.meta && Array.isArray(error.meta.errors) && error.meta.errors.length > 0){
            error.detail = `${error.meta.errors[0].message} (Code: ${error.meta.errors[0].code})`;
          }
          callback(error);
        }
      }
      break;
    case 'containOrUncontain':
      try {
        if (!options.allowContainment) {
          callback({
            detail: 'Host containment is disabled',
            status: 401
          });
          return;
        }

        const containedHost = await containHost(data, options);
        callback(null, containedHost);
      } catch (containError) {
        const err = parseErrorToReadableJSON(containError);
        Logger.error(err, 'onMessage containOrUncontain Error');
        callback(err);
      }
      break;
    case 'getAndUpdateDeviceState':
      try {
        const deviceId = payload.data.id;
        const deviceStatus = await getAndUpdateDeviceState(deviceId, options);
        callback(null, { deviceStatus });
      } catch (deviceStateError) {
        const err = parseErrorToReadableJSON(deviceStateError);
        Logger.error(err, 'onMessage getAndUpdateDeviceState Error');
        callback(err);
      }
      break;
    case 'RETRY_LOOKUP': {
      doLookup([payload.entity], options, (err, lookupResults) => {
        if (err) {
          Logger.error({ err }, 'Error retrying lookup');
          callback(err);
        } else {
          callback(
            null,
            lookupResults && lookupResults[0] && lookupResults[0].data === null
              ? { data: { summary: ['No Results Found on Retry'] } }
              : lookupResults[0]
          );
        }
      });
      break;
    }
    default:
      return;
  }
};

/**
 * Checks for an expired or invalid session error and runs back an expired session payload rather than
 * an error.
 * ```
 * {
 *     "errors": [
 *         {
 *             "code": 400,
 *             "message": "Could not find existing session"
 *         }
 *     ]
 * }
 * ```
 * @param error
 * @param callback
 * @returns {boolean}
 */
const handleExpiredRtrSession = (error, callback) => {
  if (
    error.status === 400 &&
    (error.message === 'Could not find existing session' ||
      (typeof error.description === 'object' &&
        Array.isArray(error.description.errors) &&
        error.description.errors.find(
          (error) =>
            error.message === 'Session ID is invalid' ||
            error.message === 'Could not find existing session'
        )))
  ) {
    Logger.trace(error, 'Session is expired or invalid');
    callback(null, {
      sessionExpired: true
    });
    return true;
  } else {
    return false;
  }
};

const validateStringOption = (errors, options, optionName, errMessage) => {
  if (
    typeof options[optionName].value !== 'string' ||
    (typeof options[optionName].value === 'string' &&
      options[optionName].value.length === 0)
  ) {
    errors.push({
      key: optionName,
      message: errMessage
    });
  }
};

const validateTrailingSlash = (errors, options, optionName, errMessage) => {
  if (
    typeof options[optionName].value === 'string' &&
    options[optionName].value.trim().endsWith('/')
  ) {
    errors.push({
      key: optionName,
      message: errMessage
    });
  }
};

const validateOptions = (options, callback) => {
  let errors = [];

  validateStringOption(
    errors,
    options,
    'url',
    'You must provide the Crowdstrike API url.'
  );
  validateTrailingSlash(
    errors,
    options,
    'url',
    'The url cannot end with a forward slash ("/").'
  );
  validateStringOption(errors, options, 'id', 'You must provide a Client ID.');
  validateStringOption(errors, options, 'secret', 'You must provide a Client Secret.');

  callback(null, errors);
};

module.exports = {
  doLookup,
  onMessage,
  startup,
  validateOptions
};
