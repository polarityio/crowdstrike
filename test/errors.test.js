const nock = require('nock');
const { doLookup, startup } = require('../integration');

const options = {
  url: 'https://api.twinwave.io/v1',
  apiKey: '12313',
  maxConcurrent: 20,
  minTime: 1
};

const url = {
  type: 'url',
  value: 'https://orsan.gruporhynous.com',
  isURL: true
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
  test(`${statusCode} response when calling 'https://api.twinwave.io/v1'  should return a retryable response`, (done) => {
    const params = new URLSearchParams({
      field: 'url',
      type: 'substring',
      term: 'https://orsan.gruporhynous.com'
    });

    const scope = nock(`https://api.twinwave.io/v1`).persist().get(/.*/).query(params).reply(statusCode);

    doLookup([url], options, (err, lookupResults) => {
      const details = lookupResults[0][0].data.details;
      expect(details.errorMessage).toBe(
        'A temporary TwinWave API search limit was reached. You can retry your search by pressing the "Retry Search" button.'
      );
      expect(details.summaryTag).toBe('Lookup limit reached');
      done();
    });
  });
});

// test('ECONNRESET response when calling `https://api.twinwave.io/v1` should result in a retryable response', (done) => {
//   const params = new URLSearchParams({
//     field: 'url',
//     type: 'substring',
//     term: 'https://orsan.gruporhynous.com'
//   });

//   const scope = nock(`https://api.twinwave.io/v1`)
//     .persist()
//     .get(/.*/)
//     .query(params)
//     .replyWithError({ code: 'ECONNRESET' });

//   doLookup([url], options, (err, lookupResults) => {
//     console.info(lookupResults[0][0].data.details);
//     const details = lookupResults[0][0].data.details;
//     expect(details.errorMessage).toBe(
//       'A temporary TwinWave API search limit was reached. You can retry your search by pressing the "Retry Search" button.'
//     );
//     expect(details.summaryTag).toBe('Lookup limit reached');
//     done();
//   });
// });
