const getApiData = require('./src/getApiData');
const { polarityError } = require('./src/responses');
const setRequestWithDefaults = require('./src/createRequestOptions');

let limiter = null;
let requestWithDefaults;
let Logger;

// const MAX_AUTH_RETRIES = 2;
// // Older versions of the Crowdstrike API would return a 403 if the bearer token was expired
// // newer versions now return a 401. We check for both just in case.
// const EXPIRED_BEARER_TOKEN_HTTP_CODE = 403;
// const INVALID_BEARER_TOKEN_HTTP_CODE = 401;
// const tokenCache = new Map();
// const SEVERITY_LEVELS = {
//   Critical: '"Critical"',
//   High: '"High","Critical"',
//   Medium: '"Medium","High","Critical"',
//   Low: '"Low","Medium","High","Critical"'
// };

// /**
//  * Creates the query string portion of the search request.  Note that while there is a full text search capability in
//  * the Crowdstrike API, running a full text search is too slow to use.  As a result, we are currently filtering based
//  * on different targeted fields based on the entity type to improve search performance.
//  *
//  * @param entityObj
//  * @param options
//  * @returns {} QueryString object for request
//  * @private
//  */
// function _getQuery(entityObj, options) {
//   const statuses = options.detectionStatuses.reduce((accum, statusObj) => {
//     // statuses need to be in double quotes
//     if (statusObj && statusObj.value) {
//       accum.push(`"${statusObj.value}"`);
//     }
//     return accum;
//   }, []);

//   let severityLevels = SEVERITY_LEVELS[options.minimumSeverity.value];

//   let type = 'sha256';
//   if (entityObj.isMD5) {
//     type = 'md5';
//   } else if (entityObj.type === 'custom' && entityObj.types.indexOf('custom.exeFile') >= 0) {
//     type = 'filename';
//   }

//   let filter = `+status:[${statuses.toString()}]+max_severity_displayname:[${severityLevels}]`;

//   if (entityObj.isIPv4) {
//     return {
//       limit: 10,
//       filter: `(device.external_ip:"${entityObj.value}"${filter}),(device.local_ip:"${entityObj.value}"${filter})`
//     };
//   } else {
//     return {
//       limit: 10,
//       filter: `(q:"${entityObj.value.toLowerCase()}"${filter}),(behaviors.${type}:"${entityObj.value.toLowerCase()}"${filter})`
//     };
//   }
// }

// function getIocIds(entity, options, cb) {
//   let requestOptions = {
//     uri: `${options.url}/indicators/queries/devices/v1`,
//     method: 'GET'
//   };

//   if (entity.isMD5) {
//     requestOptions.qs = { type: 'md5', value: entity.value };
//   } else if (entity.isSHA256) {
//     requestOptions.qs = { type: 'sha256', value: entity.value };
//   } else if (entity.isIPv4) {
//     requestOptions.qs = { type: 'ipv4', value: entity.value };
//   } else if (entity.isIPv6) {
//     requestOptions.qs = { type: 'ipv6', value: entity.value };
//   } else if (entity.isDomain) {
//     requestOptions.qs = { type: 'domain', value: entity.value };
//   } else {
//     return;
//   }

//   Logger.trace(requestOptions, 'searchIOCs request options');

//   authenticatedRequest(options, requestOptions, (err, response, body) => {
//     if (err) {
//       return cb(err);
//     }

//     Logger.trace(body, 'result of searchIOCs');

//     if (body.resources.length > 0) {
//       cb(null, {
//         entity: entity,
//         data: {
//           summary: [`${body.resources.length} devices`],
//           details: {
//             meta: {
//               totalResults: body.meta.pagination.total
//             },
//             deviceIds: body.resources
//           }
//         }
//       });
//     } else {
//       // Cache as a miss
//       cb(null, {
//         entity: entity,
//         data: null
//       });
//     }
//   });
// }

// function getDetectIds(entity, options, cb) {
//   let requestOptions = {
//     uri: `${options.url}/detects/queries/detects/v1`,
//     qs: _getQuery(entity, options),
//     method: 'GET'
//   };

//   Logger.trace(requestOptions, 'getDetectIds request options');

//   authenticatedRequest(options, requestOptions, (err, response, body) => {
//     if (err) {
//       return cb(err);
//     }

//     Logger.trace(body, 'result of getDetectIds');

//     if (body.resources.length > 0) {
//       cb(null, {
//         entity: entity,
//         data: {
//           summary: [`${body.resources.length} detections`],
//           details: {
//             meta: {
//               totalResults: body.meta.pagination.total
//             },
//             resourceIds: body.resources
//           }
//         }
//       });
//     } else {
//       // Cache as a miss
//       cb(null, {
//         entity: entity,
//         data: null
//       });
//     }
//   });
// }

// function getIds(entity, options, cb) {
//   async.parallel(
//     {
//       detectIds: (cb) => {
//         getDetectIds(entity, options, (err, detectIds) => {
//           cb(null, detectIds);
//         });
//       },
//       iocIds: (cb) => {
//         getIocIds(entity, options, (err, iocIds) => {
//           cb(null, iocIds);
//         });
//       }
//     },
//     (err, results) => {
//       if (err) return cb(null, err);
//       cb(null, results);
//     }
//   );
// }

// function getDevices(deviceIds, options, cb) {
//   let requestOptions = {
//     uri: `${options.url}/devices/entities/devices/v1`,
//     body: {
//       ids: deviceIds
//     },
//     json: true,
//     method: 'GET'
//   };

//   authenticatedRequest(options, requestOptions, (err, response, body) => {
//     if (err) {
//       Logger.debug({ err }, 'getDevices() return result');
//       return cb(err);
//     }

//     let devices = body.resources.map((resource) => {
//       resource.__url = `https://falcon.crowdstrike.com/investigate/events/en-US/app/eam2/investigate__computer?aid_tok=${resource.device_id}&computer=*&customer_tok=*`;
//       return resource;
//     });

//     Logger.debug({ devices }, 'getDevices() return result');

//     cb(null, devices);
//   });
// }

// function getDetects(detectIds, options, cb) {
//   let requestOptions = {
//     uri: `${options.url}/detects/entities/summaries/GET/v1`,
//     body: {
//       ids: detectIds
//     },
//     json: true,
//     method: 'POST'
//   };

//   authenticatedRequest(options, requestOptions, (err, response, body) => {
//     if (err) {
//       return cb(err);
//     }

//     let detects = body.resources.map((resource) => {
//       let split = resource.detection_id.split(':');
//       resource.__url = `https://falcon.crowdstrike.com/activity/detections/detail/${split[1]}/${split[2]}`;
//       return resource;
//     });

//     Logger.debug({ detections: detects }, 'getDetects() return result');

//     cb(null, detects);
//   });
// }

// function onDetails(lookupObject, options, cb) {
//   async.waterfall(
//     [
//       (cb) => {
//         const detectIds = _.get(lookupObject, 'data.details.detectIds.data.details.detectIds', null);
//         if (detectIds !== null) {
//           getDetects(lookupObject.data.details.detectIds.data.details.detectIds, options, (err, detects) => {
//             if (err) return cb(err);

//             lookupObject.data.details.detections = detects;

//             cb(null, lookupObject);
//           });
//         } else {
//           cb(null, lookupObject);
//         }
//       },
//       (lookupObject, cb) => {
//         const deviceIds = _.get(lookupObject, 'data.details.iocIds.data.details.deviceIds', null);
//         if (deviceIds != null) {
//           getDevices(lookupObject.data.details.iocIds.data.details.deviceIds, options, (err, devices) => {
//             if (err) return cb(err);

//             lookupObject.data.details.devices = devices;

//             cb(null, lookupObject);
//           });
//         } else {
//           cb(null, lookupObject);
//         }
//       }
//     ],
//     (err, result) => {
//       if (err) cb(null, err);
//       cb(err, result.data);
//     }
//   );
// }

// function doLookup(entities, options, cb) {
//   let lookupResults = [];
//   async.each(
//     entities,
//     (entity, next) => {
//       getIds(entity, options, (err, result) => {
//         if (err) {
//           return next(err);
//         }
//         Logger.debug({ result }, 'Received Search Detect Result');
//         lookupResults.push({
//           entity,
//           data: {
//             summary: [result.summary],
//             details: result
//           }
//         });
//         next(null);
//       });
//     },
//     (err) => {
//       Logger.trace({ lookupResults: lookupResults }, 'Returning lookup results to client');
//       cb(err, lookupResults);
//     }
//   );
// }

const startup = (logger) => {
  Logger = logger;
  requestWithDefaults = setRequestWithDefaults(Logger);
};

const doLookup = async (entities, options, callback) => {
  let response;

  try {
    for (const entity of entities) {
      response = await getApiData(requestWithDefaults, entity, options, Logger);
    }

    Logger.trace({ response }, 'DoLookup Response');
    callback(null, response);
  } catch (err) {
    return callback(polarityError(err));
  }
};

// function validateStringOption(errors, options, optionName, errMessage) {
//   if (
//     typeof options[optionName].value !== 'string' ||
//     (typeof options[optionName].value === 'string' && options[optionName].value.length === 0)
//   ) {
//     errors.push({
//       key: optionName,
//       message: errMessage
//     });
//   }
// }

// function validateTrailingSlash(errors, options, optionName, errMessage) {
//   if (typeof options[optionName].value === 'string' && options[optionName].value.trim().endsWith('/')) {
//     errors.push({
//       key: optionName,
//       message: errMessage
//     });
//   }
// }

// function validateOptions(options, callback) {
//   let errors = [];

//   validateStringOption(errors, options, 'url', 'You must provide the Crowdstrike API url.');
//   validateTrailingSlash(errors, options, 'url', 'The url cannot end with a forward slash ("/").');
//   validateStringOption(errors, options, 'id', 'You must provide a Client ID.');
//   validateStringOption(errors, options, 'secret', 'You must provide a Client Secret.');

//   callback(null, errors);
// }

module.exports = {
  doLookup: doLookup,
  startup: startup
  //   validateOptions: validateOptions,
  //   onDetails: onDetails,
  //   __generateAccessToken: generateAccessToken,
  //   __getDetectIds: getDetectIds,
  //   __getDetects: getDetects
};
