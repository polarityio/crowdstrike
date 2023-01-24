/*
 * Copyright (c) 2022, Polarity.io, Inc.
 */

const { getLogger } = require('./logger');

// Note that the tokenCache has been pulled into its own module so that we can easily
// mock these methods when testing the auth methods.

const tokenCache = new Map();

const getTokenFromCache = (options) => tokenCache.get(_getTokenKey(options));

const setTokenInCache = (options, token) => tokenCache.set(_getTokenKey(options), token);

const invalidateToken = (options) => {
  tokenCache.delete(_getTokenKey(options));
};

const _getTokenKey = (options) => options.url + options.id + options.secret;

/**
 * This method is for testing purposes only
 *
 * @param options
 */
function logToken(options) {
  const Logger = getLogger();
  let token = getTokenFromCache(options);
  if (token) {
    Logger.trace({ token }, 'Cached Token Value');
  } else {
    Logger.trace('No cached token available');
  }
}

module.exports = {
  getTokenFromCache,
  setTokenInCache,
  invalidateToken,
  logToken
};
