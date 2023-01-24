/*
 * Copyright (c) 2022, Polarity.io, Inc.
 */

const nock = require('nock');
const { startup } = require('../integration');
const generateAccessToken = require('../src/generateAccessToken');
const authenticatedRequest = require('../src/authenticatedRequest');
const { getTokenFromCache, invalidateToken } = require('../src/tokenCache');
const { TokenRequestError } = require('../src/responses');

const options = {
  url: 'https://api.crowdstrike.com',
  id: 'token',
  secret: 'token',
  searchIoc: true,
  detectionStatuses: [{ value: 'new', display: 'New' }],
  minimumSeverity: { value: 'High', display: 'High' },
  maxConcurrent: 20,
  minTime: 1
};

const Logger = {
  trace: (args, msg) => {
    //console.info(msg, args);
  },
  info: (args, msg) => {
    //console.info(msg, args);
  },
  error: (args, msg) => {
    //console.error(msg, args);
  },
  debug: (args, msg) => {
    //console.info(msg, args);
  },
  warn: (args, msg) => {
    //console.info(msg, args);
  }
};

// Mock the access token generation as we're not testing that
// This just always returns a valid auth token
jest.mock('../src/generateAccessToken', () => {
  return jest.fn(() => {
    return 'token';
  });
});

beforeAll(() => {
  startup(Logger);
});

beforeEach(() => {
  //jest.mockReset();
});

afterEach(() => {
  // After each test clear the token cache
  invalidateToken(options);
});

test(`Should return result on 200`, async () => {
  generateAccessToken.mockImplementation(() => 'mytoken'); // replace implementation

  expect.assertions(2);
  // Return a valid token but we'll simulate it being invalid
  nock(options.url).get('/authenticated-route-test').reply(200, { result: 'success' });

  const requestOptions = {
    uri: `${options.url}/authenticated-route-test`,
    json: true
  };

  const result = await authenticatedRequest(requestOptions, options);

  expect(result.statusCode).toBe(200);
  expect(result.body).toStrictEqual({
    result: 'success'
  });
});

test(`Should retry request if token is expired with 401`, async () => {
  generateAccessToken.mockImplementation(() => 'mytoken'); // replace implementation

  expect.assertions(2);
  // First call returns a 401 which means our token is expired
  nock(options.url).get('/authenticated-route-test').reply(401, { result: 'success' });
  // Second call returns a 200
  nock(options.url).get('/authenticated-route-test').reply(200, { result: 'success2' });

  const requestOptions = {
    uri: `${options.url}/authenticated-route-test`,
    json: true
  };

  const result = await authenticatedRequest(requestOptions, options);

  expect(result.statusCode).toBe(200);
  expect(result.body).toStrictEqual({
    result: 'success2'
  });
});

test(`Should retry request if token is expired with 403`, async () => {
  generateAccessToken.mockImplementation(() => 'mytoken'); // replace implementation

  expect.assertions(2);
  // First call returns a 401 which means our token is expired
  nock(options.url).get('/authenticated-route-test').reply(403, { result: 'success' });
  // Second call returns a 200
  nock(options.url).get('/authenticated-route-test').reply(200, { result: 'success2' });

  const requestOptions = {
    uri: `${options.url}/authenticated-route-test`,
    json: true
  };

  const result = await authenticatedRequest(requestOptions, options);

  expect(result.statusCode).toBe(200);
  expect(result.body).toStrictEqual({
    result: 'success2'
  });
});
