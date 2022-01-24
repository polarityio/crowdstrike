// const getDevices = async (requestWithDefaults, token, entity, options, Logger) => {
//   try {
//     const deviceIds = await getIocIds(requestWithDefaults, token, entity, options, Logger);

//     const requestOptions = {
//       uri: `${options.url}/devices/entities/devices/v1`,
//       body: {
//         ids: deviceIds
//       },
//       headers: {
//         Authorization: `Bearer ${token}`
//       },
//       json: true,
//       method: 'GET'
//     };

//     const response = await requestWithDefaults(requestOptions);

//     const devices = response.body.resources.map((resource) => {
//       resource.__url = `https://falcon.crowdstrike.com/investigate/events/en-US/app/eam2/investigate__computer?aid_tok=${resource.device_id}&computer=*&customer_tok=*`;
//       return resource;
//     });

//     return devices;
//   } catch (err) {
//     throw err;
//   }
// };

// const getIocIds = async (requestWithDefaults, token, entity, options, Logger) => {
//   const requestOptions = {
//     uri: `${options.url}/indicators/queries/devices/v1`,
//     method: 'GET',
//     headers: {
//       Authorization: `Bearer ${token}`
//     }
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

//   try {
//     const devicesIds = await requestWithDefaults(requestOptions);
//     return devicesIds;
//   } catch (err) {
//     throw err;
//   }
// };
