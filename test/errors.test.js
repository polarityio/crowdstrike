const nock = require('nock');
const _ = require('lodash');
const { doLookup, startup } = require('../integration');

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
    console.info(msg, args);
  },
  info: (args, msg) => {
    console.info(msg, args);
  },
  error: (args, msg) => {
    console.info(msg, args);
  },
  debug: (args, msg) => {
    console.info(msg, args);
  },
  warn: (args, msg) => {
    console.info(msg, args);
  }
};

beforeAll(() => {
  startup(Logger);
});

[502, 504].forEach((statusCode) => {
  test(`${statusCode} response when calling 'https://api.crowdstrike.com'  should return a retryable response`, (done) => {
    const scopeOne = nock('https://api.crowdstrike.com').post('/oauth2/token').reply(201, { access_token: 'token' });

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
      if (_.get(lookupResults, '[0].data')) {
        const details = lookupResults[0].data;
        expect(details.errorMessage).toBe(
          'A temporary Crowdstrike HX API search limit was reached. You can retry your search by pressing the "Retry Search" button.'
        );
        expect(details.summaryTag).toBe('Lookup Limit Reached');
      }
      done();
    });
  });
});

['ETIMEDOUT', 'ECONNRESET'].forEach((error) => {
  test(`${error} response when calling 'https://api.twinwave.io/v1' should result in a retryable response`, (done) => {
    const scopeOne = nock('https://api.crowdstrike.com').post('/oauth2/token').reply(201, { access_token: 'token' });

    const scopeThree = nock(
      'https://api.crowdstrike.com/detects/queries/detects/v1?limit=10&filter=%28q%3A%22b2191c32538842d3fdeff972e5a77527fa35d69fa400aad2aa2798b86fc6cf2a%22%2Bstatus%3A%5B%22new%22%5D%2Bmax_severity_displayname%3A%5B%22High%22%2C%22Critical%22%5D%29%2C%28behaviors.sha256%3A%22b2191c32538842d3fdeff972e5a77527fa35d69fa400aad2aa2798b86fc6cf2a%22%2Bstatus%3A%5B%22new%22%5D%2Bmax_severity_displayname%3A%5B%22High%22%2C%22Critical%22%5D%29'
    )
      .persist()
      .get(/.*/)
      .reply(200, { resources: ['ids'] });

    const scopeTwo = nock('https://api.crowdstrike.com/detects/entities/summaries/GET/v1')
      .post(/.*/)
      .replyWithError({ code: error });

    doLookup([sha256], options, (err, lookupResults) => {
      if (_.get(lookupResults, '[0].data')) {
        const details = lookupResults[0].data;
        expect(details.errorMessage).toBe(
          'A temporary Crowdstrike HX API search limit was reached. You can retry your search by pressing the "Retry Search" button.'
        );
        expect(details.summaryTag).toBe('Lookup Limit Reached');
      }
      done();
    });
  });
});
