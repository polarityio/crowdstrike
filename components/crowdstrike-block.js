polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  detectionProperties: ['status', 'max_confidence', 'max_severity', 'first_behavior', 'last_behavior'],
  activeTab: 'crowdstrike',
  compactDeviceProperties: [
    'platform_name',
    'os_version',
    'product_type_desc',
    'system_manufacturer',
    'hostname',
    'machine_domain'
  ],
  compactBehaviorProperties: ['scenario', 'objective', 'filename', 'tactic', 'technique', 'severity', 'confidence'],
  containmentStatus: '',
  isRunning: false,
  init() {
    const LABELS = {
      lift_containment_pending: 'Lift Containment Pending',
      containment_pending: 'Containment Pending',
      contained: 'Disconnected',
      normal: 'Connected'
    };

    let index = 0;

    const devices = this.get('block.data.details.devices');

    if (devices) {
      this.get('block.data.details.devices').forEach((device) => {
        this.set('block.data.details.devices.' + index + '.statusLabel', LABELS[device.status]);

        index += 1;
      });

      this._super(...arguments);
    }
  },
  actions: {
    changeTab: function (tabName) {
      this.set('activeTab', tabName);
    },
    retryLookup: function () {
      this.set('running', true);
      this.set('errorMessage', '');

      const payload = {
        action: 'RETRY_LOOKUP',
        entity: this.get('block.entity')
      };

      this.sendIntegrationMessage(payload)
        .then((result) => {
          if (result.data.summary) this.set('summary', result.summary);
          this.set('block.data', result.data);
        })
        .catch((err) => {
          this.set('details.errorMessage', JSON.stringify(err, null, 4));
        })
        .finally(() => {
          this.set('running', false);
        });
    },
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
    containHost: function (device, index) {
      this.sendIntegrationMessage({
        action: 'CONTAIN_HOST',
        data: { id: device.device_id, status: device.status }
      });
      this.get('block').notifyPropertyChange('data');
    }
  }
});
