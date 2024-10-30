/*
 * Copyright (c) 2022, Polarity.io, Inc.
 */

const fs = require('fs');
const request = require('postman-request');
const config = require('../config/config');
const _ = require('lodash');
const { RequestError } = require('./responses');
const _configFieldIsValid = (field) => typeof field === 'string' && field.length > 0;
const { getLogger } = require('./logger');

const checkForStatusError = (response, requestOptions) => {
  const statusCode = response.statusCode;

  if (![200, 201, 202, 404, 409, 403, 401, 429, 500, 502, 504].includes(statusCode)) {
    const errorMessage = _.get(response, 'body.errors.0.message', 'Request Error');
    const requestError = new RequestError(errorMessage, statusCode, response.body, {
      ...requestOptions,
      headers: '********'
    });
    throw requestError;
  }
};

class RequestWithDefaults {
  constructor() {
    const {
      request: { ca, cert, key, passphrase, rejectUnauthorized, proxy }
    } = config;

    const defaults = {
      ...(_configFieldIsValid(ca) && { ca: fs.readFileSync(ca) }),
      ...(_configFieldIsValid(cert) && { cert: fs.readFileSync(cert) }),
      ...(_configFieldIsValid(key) && { key: fs.readFileSync(key) }),
      ...(_configFieldIsValid(passphrase) && { passphrase }),
      ...(_configFieldIsValid(proxy) && { proxy }),
      ...(typeof rejectUnauthorized === 'boolean' && { rejectUnauthorized })
    };

    this._defaultsRequest = request.defaults(defaults);
  }

  async request(requestOptions) {
    return new Promise((resolve, reject) => {
      const Logger = getLogger();
      this._defaultsRequest(requestOptions, (err, response, body) => {
        if (err) return reject(err);
        Logger.trace({ response, requestOptions }, 'Response in requestWithDefaults');

        resolve(response);
      });
    });
  }
}

module.exports = new RequestWithDefaults();
