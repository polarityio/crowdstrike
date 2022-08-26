polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  timezone: Ember.computed('Intl', function () {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  }),
  detectionProperties: [
    'status',
    'max_confidence',
    'max_severity',
    'first_behavior',
    'last_behavior'
  ],
  activeTab: 'crowdstrike',
  compactDeviceProperties: [
    'platform_name',
    'os_version',
    'product_type_desc',
    'system_manufacturer',
    'hostname',
    'machine_domain'
  ],
  containOrUncontainMessages: {},
  containOrUncontainErrorMessages: {},
  containOrUncontainIsRunning: {},
  compactBehaviorProperties: [
    'scenario',
    'objective',
    'filename',
    'tactic',
    'technique',
    'severity',
    'confidence'
  ],
  containmentStatus: '',
  isRunning: false,
  modalDevice: {},
  init () {
    this.set(
      'activeTab',
      this.get('details.events.detections.length')
        ? 'crowdstrike'
        : this.get('block.userOptions.searchIoc') &&
          this.get('details.iocs.indicators.length')
        ? 'crowdstrikeIoc'
        : 'hosts'
    );
    // refresh the device status to ensure the containment options are always fresh
    if (this.get('details.hosts.devices')) {
      this.get('details.hosts.devices').forEach((device, index) => {
        this.doGetAndUpdateDeviceState(device, index);
      });
    }

    let array = new Uint32Array(5);
    this.set('uniqueIdPrefix', window.crypto.getRandomValues(array).join(''));

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
      this.toggleProperty(
        'details.events.detections.' + detectionIndex + '.__showAllDeviceInfo'
      );
    },
    showAllBehaviorInfo: function (detectionIndex) {
      this.toggleProperty(
        'details.events.detections.' + detectionIndex + '.__showAllBehaviorInfo'
      );
    },
    toggleShowModal: function (device, index) {
      this.toggleProperty('details.hosts.devices.' + index + '.__modalOpen');
      this.set('modalDevice', { device, index });
    },
    confirmContainmentOrLiftContainment: function () {
      const outerThis = this;
      const { device, index } = this.get('modalDevice');

      this.setMessages(index, 'getAndUpdateDeviceState', '');
      this.setErrorMessages(index, 'getAndUpdateDeviceState', '');
      this.setIsRunning(index, 'getAndUpdateDeviceState', true);
      this.set('details.hosts.devices.' + index + '.__modalOpen', false);

      this.sendIntegrationMessage({
        action: 'containOrUncontain',
        data: { id: device.device_id, status: device.status }
      })
        .then(({ updatedDeviceState }) => {
          this.set('details.hosts.devices.' + index + '.status', updatedDeviceState);
          let message = 'Containment successfully started.';
          if (device.status === 'lift_containment_pending') {
            message = 'Lift containment successfully started';
          }
          outerThis.setMessages(index, 'getAndUpdateDeviceState', message);
        })
        .catch((err) => {
          outerThis.setErrorMessages(index, 'getAndUpdateDeviceState', `Failed ${err}`);
        })
        .finally(() => {
          this.setIsRunning(index, 'getAndUpdateDeviceState', false);
          outerThis.get('block').notifyPropertyChange('data');

          setTimeout(() => {
            outerThis.setMessages(index, 'getAndUpdateDeviceState', '');
            outerThis.setErrorMessages(index, 'getAndUpdateDeviceState', '');
            outerThis.get('block').notifyPropertyChange('data');
          }, 5000);
        });
    },
    getAndUpdateDeviceState: function (device, index) {
      this.doGetAndUpdateDeviceState(device, index);
    }
  },
  setMessages: function (index, prefix, message) {
    if (!this.isDestroyed) {
      this.set(
        `${prefix}Messages`,
        Object.assign({}, this.get(`${prefix}Messages`), { [index]: message })
      );
    }
  },
  setErrorMessages: function (index, prefix, message) {
    if (!this.isDestroyed) {
      this.set(
        `${prefix}ErrorMessages`,
        Object.assign({}, this.get(`${prefix}ErrorMessages`), {
          [index]: message
        })
      );
    }
  },
  flashElement: function (element, flashCount = 3, flashTime = 280) {
    if (!this.isDestroyed) {
      if (!flashCount) return;
      element.classList.add('highlight');
      setTimeout(() => {
        element.classList.remove('highlight');
        setTimeout(() => this.flashElement(element, flashCount - 1), flashTime);
      }, flashTime);
    }
  },
  setIsRunning: function (index, prefix, value) {
    if (!this.isDestroyed) {
      this.set(
        `${prefix}IsRunning`,
        Object.assign({}, this.get(`${prefix}IsRunning`), { [index]: value })
      );
    }
  },
  doGetAndUpdateDeviceState: function (device, index) {
    this.setIsRunning(index, 'getAndUpdateDeviceState', true);
    this.setMessages(index, 'getAndUpdateDeviceState', '');
    this.setErrorMessages(index, 'getAndUpdateDeviceState', '');

    this.sendIntegrationMessage({
      action: 'getAndUpdateDeviceState',
      data: { id: device.device_id }
    })
      .then(({ deviceStatus }) => {
        this.set('details.hosts.devices.' + index + '.status', deviceStatus);
        if (!['normal', 'contained'].includes(deviceStatus)) {
          if (device.status === 'lift_containment_pending') {
            this.setMessages(
              index,
              'getAndUpdateDeviceState',
              'Lift Containment Still Pending ...'
            );
          } else {
            this.setMessages(
              index,
              'getAndUpdateDeviceState',
              'Containment Still Pending ...'
            );
          }
          let element = document.getElementById(
            `device-${this.get('uniqueIdPrefix')}-${index}`
          );
          // element can be null here if the user is no on the tab with the device information
          // so we want to guard against that.
          if (element) {
            this.flashElement(element);
          }
        }
      })
      .catch((err) => {
        this.setErrorMessages(index, 'getAndUpdateDeviceState', `${err}`);
      })
      .finally(() => {
        this.setIsRunning(index, 'getAndUpdateDeviceState', false);
        this.get('block').notifyPropertyChange('data');
        setTimeout(() => {
          this.setMessages(index, 'getAndUpdateDeviceState', '');
          this.setErrorMessages(index, 'getAndUpdateDeviceState', '');
          this.get('block').notifyPropertyChange('data');
        }, 5000);
      });
  }
});
