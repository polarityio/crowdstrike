const SEVERITY_LEVELS_FOR_DETECTIONS = {
  Critical: '"Critical"',
  High: '"High","Critical"',
  Medium: '"Medium","High","Critical"',
  Low: '"Low","Medium","High","Critical"'
};

const SEVERITY_LEVELS_FOR_INDICATORS = {
  Critical: '"high"',
  High: '"high"',
  Medium: '"medium","high"',
  Low: '"low","medium","high"'
};


module.exports = {
  SEVERITY_LEVELS_FOR_DETECTIONS,
  SEVERITY_LEVELS_FOR_INDICATORS
};