const nock = require('nock');
const { doLookup, startup } = require('../integration');
const { invalidateToken } = require('../src/tokenCache');
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

const sha256 = {
  type: 'sha256',
  value: 'b2191c32538842d3fdeff972e5a77527fa35d69fa400aad2aa2798b86fc6cf2a',
  isSHA256: true
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

// jest.mock('../src/tokenCache', () => {
//   const actualModule = jest.requireActual('../src/tokenCache');
//   const mockedFunctions = {
//     ...actualModule,
//     // Return null which effectively disables token caching which makes testing
//     // easier
//     getTokenFromCache: jest.fn(() => {
//       return null;
//     })
//   };
//   return mockedFunctions;
// });

beforeAll(() => {
  startup(Logger);
});

afterEach(() => {
  // After each test clear the token cache
  invalidateToken(options);
});


test(`Multiple 401 responses are treated as a failure to auth`, (done) => {
  expect.assertions(2);
  // Return a valid token but we'll simulate it being invalid
  const firstAuthAttempt = nock('https://api.crowdstrike.com')
    .post('/oauth2/token')
    .times(2)
    .reply(201, { access_token: 'token' });

  // Return a 401 which should invalidate the token and trigger another auth attempt
  // We try a second time to auth and then finally fail with an error.
  const getDetectIds = nock(
    'https://api.crowdstrike.com/detects/queries/detects/v1?limit=10&filter=%28q%3A%22b2191c32538842d3fdeff972e5a77527fa35d69fa400aad2aa2798b86fc6cf2a%22%2Bstatus%3A%5B%22new%22%5D%2Bmax_severity_displayname%3A%5B%22High%22%2C%22Critical%22%5D%29%2C%28behaviors.sha256%3A%22b2191c32538842d3fdeff972e5a77527fa35d69fa400aad2aa2798b86fc6cf2a%22%2Bstatus%3A%5B%22new%22%5D%2Bmax_severity_displayname%3A%5B%22High%22%2C%22Critical%22%5D%29'
  )
    .get(/.*/)
    .times(2)
    .reply(401);

  doLookup([sha256], options, (err, lookupResults) => {
    expect(err.message).toBe(
      'Attempted to authenticate 2 times but failed authentication'
    );
    expect(err.status).toBe(401);
    done();
  });
});

test(`401 response authenticating to get a token should return an error`, (done) => {
  expect.assertions(2);
  const firstAuthAttempt = nock('https://api.crowdstrike.com')
    .post('/oauth2/token')
    .reply(401);

  doLookup([sha256], options, (err, lookupResults) => {
    expect(err.message).toBe('The provided Client ID is not valid (status: 401)');
    expect(err.status).toBe(401);
    done();
  });
});

test(`400 response authenticating to get a token should return an auth error`, (done) => {
  expect.assertions(2);
  const firstAuthAttempt = nock('https://api.crowdstrike.com')
    .post('/oauth2/token')
    .reply(400);

  doLookup([sha256], options, (err, lookupResults) => {
    expect(err.message).toBe('The provided Client ID is not valid (status: 400)');
    expect(err.status).toBe(400);
    done();
  });
});

test(`403 response authenticating to get a token should return a permissions error`, (done) => {
  expect.assertions(2);
  const firstAuthAttempt = nock('https://api.crowdstrike.com')
    .post('/oauth2/token')
    .reply(403);

  doLookup([sha256], options, (err, lookupResults) => {
    expect(err.message).toBe(
      'The provided Client Secret does not match the provided Client Id'
    );
    expect(err.status).toBe(403);
    done();
  });
});

test(`Any unexpected response when authenticating to get a token should return an error`, (done) => {
  expect.assertions(2);
  const firstAuthAttempt = nock('https://api.crowdstrike.com')
    .post('/oauth2/token')
    .reply(404);

  doLookup([sha256], options, (err, lookupResults) => {
    expect(err.message).toBe('Unexpected error getting auth token (status: 404)');
    expect(err.status).toBe(404);
    done();
  });
});

[500, 502, 504].forEach((statusCode) => {
  //console.info('Executing test for ' + statusCode);
  test(`${statusCode} response when calling 'https://api.crowdstrike.com' should return a retryable response`, (done) => {
    expect.assertions(2);
    const getAuthToken = nock('https://api.crowdstrike.com')
      .post('/oauth2/token')
      .reply(201, { access_token: 'token' });

    const getDetectIds = nock(
      'https://api.crowdstrike.com/detects/queries/detects/v1?limit=10&filter=%28q%3A%22b2191c32538842d3fdeff972e5a77527fa35d69fa400aad2aa2798b86fc6cf2a%22%2Bstatus%3A%5B%22new%22%5D%2Bmax_severity_displayname%3A%5B%22High%22%2C%22Critical%22%5D%29%2C%28behaviors.sha256%3A%22b2191c32538842d3fdeff972e5a77527fa35d69fa400aad2aa2798b86fc6cf2a%22%2Bstatus%3A%5B%22new%22%5D%2Bmax_severity_displayname%3A%5B%22High%22%2C%22Critical%22%5D%29'
    )
      .persist()
      .get(/.*/)
      .reply(200, { resources: ['ids'] });

    const getDetects = nock(
      'https://api.crowdstrike.com/detects/entities/summaries/GET/v1'
    )
      .post(/.*/)
      .reply(statusCode, { resources: [{ detection_id: '1231' }] });

    doLookup([sha256], options, (err, lookupResults) => {
      const data = lookupResults[0].data;
      expect(data.details.errorMessage).toBe(
        'The CrowdStrike API server experienced a temporary error'
      );
      expect(data.details.status).toBe(statusCode);
      done();
    });
  });
});

// General Errors

test(`400 response when calling 'https://api.crowdstrike.com' should return an Error`, (done) => {
  expect.assertions(2);
  const scopeOne = nock('https://api.crowdstrike.com')
    .post('/oauth2/token')
    .reply(201, { access_token: 'token' });

  const scopeThree = nock(
    'https://api.crowdstrike.com/detects/queries/detects/v1?limit=10&filter=%28q%3A%22b2191c32538842d3fdeff972e5a77527fa35d69fa400aad2aa2798b86fc6cf2a%22%2Bstatus%3A%5B%22new%22%5D%2Bmax_severity_displayname%3A%5B%22High%22%2C%22Critical%22%5D%29%2C%28behaviors.sha256%3A%22b2191c32538842d3fdeff972e5a77527fa35d69fa400aad2aa2798b86fc6cf2a%22%2Bstatus%3A%5B%22new%22%5D%2Bmax_severity_displayname%3A%5B%22High%22%2C%22Critical%22%5D%29'
  )
    .persist()
    .get(/.*/)
    .reply(200, { resources: ['ids'] });

  const scopeTwo = nock('https://api.crowdstrike.com/detects/entities/summaries/GET/v1')
    .post(/.*/)
    .reply(400, { resources: [{ detection_id: '1231' }] });

  doLookup([sha256], options, (err, lookupResults) => {
    expect(err.status).toBe(400);
    expect(err.message).toBe(`Unexpected HTTP status code received (400)`);
    done();
  });
});

// API Limit Reached Codes
[429].forEach((statusCode) => {
  //console.info('Executing test for ' + statusCode);
  test(`${statusCode} response when calling 'https://api.crowdstrike.com' should return a retryable response`, (done) => {
    expect.assertions(2);
    const scopeOne = nock('https://api.crowdstrike.com')
      .post('/oauth2/token')
      .reply(201, { access_token: 'token' });

    const scopeThree = nock(
      'https://api.crowdstrike.com/detects/queries/detects/v1?limit=10&filter=%28q%3A%22b2191c32538842d3fdeff972e5a77527fa35d69fa400aad2aa2798b86fc6cf2a%22%2Bstatus%3A%5B%22new%22%5D%2Bmax_severity_displayname%3A%5B%22High%22%2C%22Critical%22%5D%29%2C%28behaviors.sha256%3A%22b2191c32538842d3fdeff972e5a77527fa35d69fa400aad2aa2798b86fc6cf2a%22%2Bstatus%3A%5B%22new%22%5D%2Bmax_severity_displayname%3A%5B%22High%22%2C%22Critical%22%5D%29'
    )
      .persist()
      .get(/.*/)
      .reply(200, { resources: ['ids'] });

    const scopeTwo = nock('https://api.crowdstrike.com/detects/entities/summaries/GET/v1')
      .post(/.*/)
      .reply(statusCode, { resources: [{ detection_id: '1231' }] });

    doLookup([sha256], options, (err, lookupResults) => {
      const data = lookupResults[0].data;
      expect(data.details.errorMessage).toBe(`Temporary API Search Limit Reached`);
      expect(data.details.status).toBe(statusCode);
      done();
    });
  });
});

// Network errors that allow retry
['ETIMEDOUT', 'ECONNRESET'].forEach((code) => {
  test(`${code} response when calling 'https://api.twinwave.io/v1' should result in a retryable response`, (done) => {
    expect.assertions(2);
    const scopeOne = nock('https://api.crowdstrike.com')
      .post('/oauth2/token')
      .reply(201, { access_token: 'token' });

    const scopeThree = nock(
      'https://api.crowdstrike.com/detects/queries/detects/v1?limit=10&filter=%28q%3A%22b2191c32538842d3fdeff972e5a77527fa35d69fa400aad2aa2798b86fc6cf2a%22%2Bstatus%3A%5B%22new%22%5D%2Bmax_severity_displayname%3A%5B%22High%22%2C%22Critical%22%5D%29%2C%28behaviors.sha256%3A%22b2191c32538842d3fdeff972e5a77527fa35d69fa400aad2aa2798b86fc6cf2a%22%2Bstatus%3A%5B%22new%22%5D%2Bmax_severity_displayname%3A%5B%22High%22%2C%22Critical%22%5D%29'
    )
      .persist()
      .get(/.*/)
      .reply(200, { resources: ['ids'] });

    const scopeTwo = nock('https://api.crowdstrike.com/detects/entities/summaries/GET/v1')
      .post(/.*/)
      .replyWithError({ code });

    doLookup([sha256], options, (err, lookupResults) => {
      const data = lookupResults[0].data;
      expect(data.details.errorMessage).toBe(
        'The CrowdStrike API server experienced a connection error.'
      );
      expect(data.details.status).toBe(code);
      done();
    });
  });
});
