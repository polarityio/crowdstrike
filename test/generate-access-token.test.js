/*
 * Copyright (c) 2022, Polarity.io, Inc.
 */

const nock = require('nock');
const { startup } = require('../integration');
const generateAccessToken = require('../src/generateAccessToken');
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

beforeAll(() => {
  startup(Logger);
});

afterEach(() => {
  // After each test clear the token cache
  invalidateToken(options);
});

test(`Token should be cached after first auth`, async () => {
  expect.assertions(2);
  // Return a valid token but we'll simulate it being invalid
  const firstAuthAttempt = nock('https://api.crowdstrike.com')
    .post('/oauth2/token')
    .reply(201, { access_token: 'mytoken' });

  const result = await generateAccessToken(options);
  const token = getTokenFromCache(options);
  expect(result).toBe('mytoken');
  expect(token).toBe('mytoken');
});

test(`Token should be regenerated after being invalidated`, async () => {
  expect.assertions(2);
  // Return a valid token but we'll simulate it being invalid
  nock('https://api.crowdstrike.com')
    .post('/oauth2/token')
    .reply(201, { access_token: 'first_token' });

  nock('https://api.crowdstrike.com')
    .post('/oauth2/token')
    .reply(201, { access_token: 'second_token' });

  await generateAccessToken(options);
  const firstToken = getTokenFromCache(options);
  invalidateToken(options);
  await generateAccessToken(options);
  const secondToken = getTokenFromCache(options);
  expect(firstToken).toBe('first_token');
  expect(secondToken).toBe('second_token');
});

test(`Should return token request error on 401 response`, async () => {
  expect.assertions(2);
  // Return a valid token but we'll simulate it being invalid
  nock('https://api.crowdstrike.com').post('/oauth2/token').reply(401);

  try {
    await generateAccessToken(options);
  } catch (err) {
    expect(err instanceof TokenRequestError).toBe(true);
    expect(err.message).toBe('The provided Client ID is not valid (status: 401)');
  }
});

test(`Should return token request error on 400 response`, async () => {
  expect.assertions(2);
  // Return a valid token but we'll simulate it being invalid
  nock('https://api.crowdstrike.com').post('/oauth2/token').reply(400);

  try {
    await generateAccessToken(options);
  } catch (err) {
    expect(err instanceof TokenRequestError).toBe(true);
    expect(err.message).toBe('The provided Client ID is not valid (status: 400)');
  }
});

test(`Should return token request error on a 500 response`, async () => {
  expect.assertions(2);
  // Return a valid token but we'll simulate it being invalid
  nock('https://api.crowdstrike.com').post('/oauth2/token').reply(500);

  try {
    await generateAccessToken(options);
  } catch (err) {
    expect(err instanceof TokenRequestError).toBe(true);
    expect(err.message).toBe('Unexpected error getting auth token (status: 500)');
  }
});

test(`Should return token request error on 403 response`, async () => {
  expect.assertions(2);
  // Return a valid token but we'll simulate it being invalid
  nock('https://api.crowdstrike.com').post('/oauth2/token').reply(403);

  try {
    await generateAccessToken(options);
  } catch (err) {
    expect(err instanceof TokenRequestError).toBe(true);
    expect(err.message).toBe(
      'The provided Client Secret does not match the provided Client Id'
    );
  }
});
