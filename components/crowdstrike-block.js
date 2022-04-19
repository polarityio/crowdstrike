polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  timezone: Ember.computed('Intl', function () {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  }),
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
  modalOpen: false,
  containOrUncontainMessages: {},
  containOrUncontainErrorMessages: {},
  containOrUncontainIsRunning: {},
  compactBehaviorProperties: ['scenario', 'objective', 'filename', 'tactic', 'technique', 'severity', 'confidence'],
  containmentStatus: '',
  isRunning: false,
  modalDevice: {},
  init() {
    this.set(
      'activeTab',
      this.get('details.events.detections.length')
        ? 'crowdstrike'
        : this.get('block.userOptions.searchIoc')
        ? 'crowdstrikeIoc'
        : 'hosts'
    );

    this._super(...arguments);
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
      let detection = this.get('details.events.' + detectionIndex);
      let __viewAllDeviceInfo = this.get('details.events.' + detectionIndex + '.__showAllDeviceInfo');
      if (__viewAllDeviceInfo) {
        Ember.set(detection, '__showAllDeviceInfo', false);
      } else {
        Ember.set(detection, '__showAllDeviceInfo', true);
      }
    },
    showAllBehaviorInfo: function (detectionIndex) {
      let detection = this.get('details.events.' + detectionIndex);
      let __showAllBehaviorInfo = this.get('details.events.' + detectionIndex + '.__showAllBehaviorInfo');
      if (__showAllBehaviorInfo) {
        Ember.set(detection, '__showAllBehaviorInfo', false);
      } else {
        Ember.set(detection, '__showAllBehaviorInfo', true);
      }
    },
    toggleShowModal: function (device, index) {
      this.toggleProperty('modalOpen');

      if (device) this.set('modalDevice', { device, index });
    },
    confirmContainmentOrLiftContainment: function () {
      const outerThis = this;

      const { device, index } = this.get('modalDevice');

      this.setMessages(index, 'containOrUncontain', '');
      this.setErrorMessages(index, 'containOrUncontain', '');
      this.setIsRunning(index, 'containOrUncontain', true);
      this.set('modalOpen', false);

      this.sendIntegrationMessage({
        action: 'containOrUncontain',
        data: { id: device.device_id, status: device.status }
      })
        .then(({ updatedDeviceState }) => {
          this.set('details.hosts.devices.' + index + '.status', updatedDeviceState);
        })
        .catch((err) => {
          console.log(err);
          outerThis.setErrorMessages(
            index,
            'containOrUncontain',
            `
            Failed ${err}

            `
          );
        })
        .finally(() => {
          this.setIsRunning(index, 'containOrUncontain', false);
          outerThis.get('block').notifyPropertyChange('data');

          setTimeout(() => {
            outerThis.setMessages(index, 'containOrUncontain', '');
            outerThis.setErrorMessages(index, 'containOrUncontain', '');
            outerThis.get('block').notifyPropertyChange('data');
          }, 5000);
        });
    },
    getAndUpdateDeviceState: function (device, index) {
      this.setIsRunning(index, 'getAndUpdateDeviceState', true);
      this.sendIntegrationMessage({
        action: 'getAndUpdateDeviceState',
        data: { id: device.device_id }
      })
        .then(({ deviceStatus }) => {
          this.set('details.hosts.' + index + '.status', deviceStatus);
          if (!['normal', 'contained'].includes(deviceStatus))
            this.setMessages(index, 'getAndUpdateDeviceState', 'Still Pending...');
        })
        .catch((err) => {
          this.setErrorMessages(index, 'getAndUpdateDeviceState', `${err}`);
        })
        .finally(() => {
          this.setIsRunning(index, 'getAndUpdateDeviceState', false);
          this.get('block').notifyPropertyChange('data');
          setTimeout(() => {
            this.setMessages(index, 'getAndUpdateDeviceState', '');
            this.get('block').notifyPropertyChange('data');
          }, 5000);
        });
    }
  },
  setMessages: function (index, prefix, message) {
    console.log(index, prefix, message);
    this.set(`${prefix}Messages`, Object.assign({}, this.get(`${prefix}Messages`), { [index]: message }));
  },
  setErrorMessages: function (index, prefix, message) {
    this.set(
      `${prefix}ErrorMessages`,
      Object.assign({}, this.get(`${prefix}ErrorMessages`), {
        [index]: message
      })
    );
  },
  toggleModal: function () {
    if (!this.get('modalOpen')) {
    }
  },
  setIsRunning: function (index, prefix, value) {
    console.log(`${prefix}IsRunning`, Object.assign({}, this.get(`${prefix}IsRunning`), { [index]: value }));
    this.set(`${prefix}IsRunning`, Object.assign({}, this.get(`${prefix}IsRunning`), { [index]: value }));
  }
});
