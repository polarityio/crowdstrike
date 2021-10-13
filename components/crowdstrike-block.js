polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  detectionProperties: ['status', 'max_confidence', 'max_severity', 'first_behavior', 'last_behavior'],
  compactDeviceProperties: [
    'platform_name',
    'os_version',
    'product_type_desc',
    'system_manufacturer',
    'hostname',
    'machine_domain'
  ],
  // init: function () {
  //   this._super(...arguments);
  //   if (block.data.details && block.data.details.devices) {

  //     this.get('block.data.details.devices').forEach((result) => {
  //       Ember.set(result, 'showCrowdstrikeIoc', false);
  //       Ember.set(result, 'showCrowdstrike', true);
  //     });
  //   }
  // },
  compactBehaviorProperties: ['scenario', 'objective', 'filename', 'tactic', 'technique', 'severity', 'confidence'],
  actions: {
    showAllDeviceInfo: function (detectionIndex) {
      let detection = this.get('details.detections.' + detectionIndex);
      let __viewAllDeviceInfo = this.get('details.detections.' + detectionIndex + '.__showAllDeviceInfo');
      if (__viewAllDeviceInfo) {
        Ember.set(detection, '__showAllDeviceInfo', false);
      } else {
        Ember.set(detection, '__showAllDeviceInfo', true);
      }
    },
    showAllBehaviorInfo: function (detectionIndex) {
      let detection = this.get('details.detections.' + detectionIndex);
      let __showAllBehaviorInfo = this.get('details.detections.' + detectionIndex + '.__showAllBehaviorInfo');
      if (__showAllBehaviorInfo) {
        Ember.set(detection, '__showAllBehaviorInfo', false);
      } else {
        Ember.set(detection, '__showAllBehaviorInfo', true);
      }
    },
    showCrowdstrike: function (index) {
      this.set('block.data.details.' + index + '.showCrowdstrikeIoc', false);
      this.set('block.data.details.' + index + '.showCrowdstrike', true);
    },
    showCrowdstrikeIoc: function (index) {
      this.set('block.data.details.' + index + '.showCrowdstrikeIoc', true);
      this.set('block.data.details.' + index + '.showCrowdstrike', false);
    }
  }
});
