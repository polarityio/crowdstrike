polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  state: Ember.computed.alias('block._state'),
  timezone: Ember.computed('Intl', function () {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  }),
  activeTab: 'crowdstrike',
  containOrUncontainMessages: {},
  containOrUncontainErrorMessages: {},
  containOrUncontainIsRunning: {},
  containmentStatus: '',
  isRunning: false,
  uniqueIfPrefix: '',
  modalDevice: {},
  init() {
    this.initActiveTab();

    // refresh the device status to ensure the containment options are always fresh
    // and not being served from the cache
    if (this.get('details.hosts.devices')) {
      this.get('details.hosts.devices').forEach((device, index) => {
        this.doGetAndUpdateDeviceState(device, index);
      });
    }

    if (!this.get('block._state')) {
      this.set('block._state', {});
      this.set('state.rtr', {});
      this.set('state.rtr.consoleMessages', Ember.A());
      this.set('state.rtr.connectionStatus', 'Disconnected');
      this.set('state.rtr.isConnected', false);
    }

    let array = new Uint32Array(5);
    this.set('uniqueIdPrefix', window.crypto.getRandomValues(array).join(''));

    this._super(...arguments);
  },
  initActiveTab() {
    this.set(
      'activeTab',
      this.get('details.events.detections.length')
        ? 'crowdstrike'
        : this.get('block.userOptions.searchIoc') &&
          this.get('details.iocs.indicators.length')
        ? 'crowdstrikeIoc'
        : 'hosts'
    );
  },
  actions: {
    changeTab: function (tabName) {
      this.set('activeTab', tabName);
    },
    changeScriptTab: function (tabName) {
      if (this.get('activeScriptTab') === tabName) {
        this.set('activeScriptTab', '');
      } else {
        this.set('activeScriptTab', tabName);
      }
    },
    viewFalconScriptDetails: function (falconScriptIndex) {
      this.toggleProperty(`details.falconScripts.${falconScriptIndex}.__viewDetails`);
    },
    viewCustomScriptDetails: function (customScriptIndex) {
      this.toggleProperty(`details.customScripts.${customScriptIndex}.__viewDetails`);
    },
    // Triggered when the user selects a device in the device drop down of the RTR tab
    deviceSelected: function () {
      const selectedDeviceId = this.get('state.rtr.selectedDeviceId');
      const selectedDevice = this.get('details.hosts.devices').find(
        (device) => device.device_id === selectedDeviceId
      );
      this.set('state.rtr.selectedDevice', selectedDevice);
    },
    // Triggered when the user selects a FalconScript to populate into the command input
    populateFalconScript: function (falconScriptIndex) {
      const script = this.get(`details.falconScripts.${falconScriptIndex}`);
      this.set('state.rtr.selectedFalconScriptId', falconScriptIndex);
      this.set('state.rtr.selectedCustomScriptId', '');
      this.set(
        'state.rtr.command',
        `falconscript -Name=${script.name} -JsonInput=\`\`\`''\`\`\``
      );
    },
    // Triggered when the user selects a CustomScript to populate into the command input
    populateCustomScript: function (customScriptIndex) {
      const script = this.get(`details.customScripts.${customScriptIndex}`);
      this.set('state.rtr.selectedCustomScriptId', customScriptIndex);
      this.set('state.rtr.selectedFalconScriptId', '');
      this.set(
        'state.rtr.command',
        `runscript -CloudFile="${script.name}"  -CommandLine=""`
      );
    },
    connectToDevice(deviceId) {
      this.set('state.rtr.isConnecting', true);
      this.get('state.rtr.consoleMessages').clear();
      const payload = {
        action: 'GET_RTR_SESSION',
        deviceId
      };
      this.sendIntegrationMessage(payload)
        .then((result) => {
          console.info('Connect to Device', result);
          this.set('state.rtr.sessionId', result.sessionId);
          this.set('state.rtr.pwd', result.pwd);
          this.set('state.rtr.connectionStatus', 'Connected');
          this.set('state.rtr.isConnected', true);
          this.set('state.rtr.showConsolePwd', true);
        })
        .catch((err) => {
          console.error(err);
          this.set('state.rtr.connectionStatus', 'Disconnected');
          this.set('state.rtr.isConnected', false);
        })
        .finally(() => {
          this.set('state.rtr.isConnecting', false);
        });
    },
    copyMessageValue: function (elementId, messageIndex) {
      Ember.run.scheduleOnce('afterRender', this, this.copyElementToClipboard, elementId);

      Ember.run.scheduleOnce('destroy', this, this.restoreCopyState, messageIndex);
    },
    disconnectFromDevice(sessionId) {
      if (!sessionId) {
        console.warn('No session id provided when calling `disconnectFromDevice` action');
        return;
      }

      this.set('state.rtr.isDisconnecting', true);
      const payload = {
        action: 'DELETE_RTR_SESSION',
        sessionId
      };
      this.sendIntegrationMessage(payload)
        .then((result) => {
          this.set('state.rtr.sessionId', undefined);
          this.set('state.rtr.connectionStatus', 'Disconnected');
          this.set('state.rtr.isConnected', false);
          this.set('state.rtr.showConsolePwd', false);
          this.addConsoleMessage(
            'system',
            `Disconnected from host ${this.get('state.rtr.selectedDevice.hostname')}`
          );
        })
        .catch((err) => {
          console.error(err);
          this.set('state.rtr.connectionStatus', 'Disconnected');
          this.set('state.rtr.isConnected', false);
        })
        .finally(() => {
          this.set('state.rtr.isDisconnecting', false);
        });
    },
    runScript: async function (sessionId, deviceId, commandString) {
      if (this.get('state.rtr.isRunningCommand')) {
        // a command is already running
        return;
      }

      if (!sessionId) {
        console.warn('No session id provided when calling `runScript` action');
        return;
      }

      if (!deviceId) {
        console.warn('No device id available when calling `runScript` action');
      }

      if (!commandString) {
        console.warn('No command string provided when calling `runScript` action');
      }

      this.scrollToEndOfConsole();

      commandString = commandString.trim();

      this.set('state.rtr.isRunningCommand', true);
      this.set('state.rtr.commandStatus', 'Sending command');

      this.set('state.rtr.showConsolePwd', false);
      this.set('state.rtr.command', '');
      this.addConsoleMessage('command', `${this.get('state.rtr.pwd')} ${commandString}`);

      try {
        let baseCommand = commandString;

        if (commandString.startsWith('runscript')) {
          baseCommand = 'runscript';
        } else if (commandString.startsWith('falconscript')) {
          baseCommand = 'falconScript';
        }

        const getCloudRequestIdResult = await this.getCloudRequestId(
          sessionId,
          deviceId,
          baseCommand,
          commandString
        );

        if (getCloudRequestIdResult.sessionExpired) {
          this.addConsoleMessage(
            'error',
            'Your session has expired.  You must connect to the host again.'
          );
          this.set('state.rtr.isRunningCommand', false);
          this.set('state.rtr.isConnected', false);
          this.set('state.rtr.showConsolePwd', false);
          this.addConsoleMessage(
            'system',
            `Disconnected from host ${this.get('state.rtr.selectedDevice.hostname')}`
          );
          return;
        }

        this.set(
          'state.rtr.commandStatus',
          `Waiting for result: ${getCloudRequestIdResult.cloudRequestId}`
        );

        let result = await this.getRtrResult(getCloudRequestIdResult.cloudRequestId);

        if (result.sessionExpired) {
          this.addConsoleMessage(
            'error',
            'Your session has expired.  You must connect to the host again.'
          );
          this.set('state.rtr.isRunningCommand', false);
          this.set('state.rtr.isConnected', false);
          this.set('state.rtr.showConsolePwd', false);
          this.addConsoleMessage(
            'system',
            `Disconnected from host ${this.get('state.rtr.selectedDevice.hostname')}`
          );
          return;
        }

        let resultType = 'commandResult';
        if (baseCommand === 'falconscript' || baseCommand === 'runscript') {
          resultType = 'scriptResult';
        }
        let parsedResult;
        let resultText = result.stdout;
        if (result.stderr) {
          resultText = result.stderr;
          resultType = 'error';
        }
        try {
          // Some commands return results as JSON.  We try to parse the result as JSON and if that
          // fails we treat the result as a string.
          parsedResult = JSON.parse(resultText);
          if (Array.isArray(parsedResult.result)) {
            // Most falcon scripts return a `result` array which we check for here
            this.addConsoleMessage(resultType, parsedResult.result);
          } else {
            // This is our backup where we can't determine the format of the returned data but we know its JSON
            this.addConsoleMessage(resultType, JSON.stringify(parsedResult, null, 2));
          }
        } catch (parseError) {
          // Finally, we couldn't parse the result as JSON so we just treat it as a string
          this.addConsoleMessage(resultType, resultText);
        }
        this.set('state.rtr.showConsolePwd', true);
      } catch (error) {
        console.error(error);
        this.addConsoleMessage(
          'error',
          error.message ? error.message : JSON.stringify(error, null, 2)
        );
        this.set('state.rtr.showConsolePwd', true);
      } finally {
        this.set('state.rtr.isRunningCommand', false);
        this.set('state.rtr.commandStatus', '');
      }
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
          this.initActiveTab();
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
  copyElementToClipboard(element) {
    window.getSelection().removeAllRanges();
    let range = document.createRange();

    range.selectNode(
      typeof element === 'string' ? document.getElementById(element) : element
    );
    window.getSelection().addRange(range);
    document.execCommand('copy');
    window.getSelection().removeAllRanges();
  },
  restoreCopyState(messageIndex) {
    this.set(`state.rtr.consoleMessages.${messageIndex}.showCopyMessage`, true);

    setTimeout(() => {
      if (!this.isDestroyed) {
        this.set(`state.rtr.consoleMessages.${messageIndex}.showCopyMessage`, false);
      }
    }, 2000);
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
      const error = Object.assign({}, this.get(`${prefix}ErrorMessages`), {
        [index]: message
      });
      this.set(`${prefix}ErrorMessages`, error);
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
        //console.info(`Received updated status: ${deviceStatus}`);
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
        if (typeof err === 'string') {
          this.setErrorMessages(index, 'getAndUpdateDeviceState', err);
        } else {
          this.setErrorMessages(
            index,
            'getAndUpdateDeviceState',
            `${JSON.stringify(err, null, 4)}`
          );
        }
      })
      .finally(() => {
        this.setIsRunning(index, 'getAndUpdateDeviceState', false);
        this.get('block').notifyPropertyChange('data');
        setTimeout(() => {
          this.setMessages(index, 'getAndUpdateDeviceState', '');
          this.get('block').notifyPropertyChange('data');
        }, 5000);
      });
  },
  getCloudRequestId: function (sessionId, deviceId, baseCommand, commandString) {
    return new Ember.RSVP.Promise((resolve, reject) => {
      if (!sessionId) {
        return reject('No session id provided when calling `getCloudRequestId` action');
      }

      if (!deviceId) {
        return reject('No device id available when calling `getCloudRequestId` action');
      }

      if (!commandString) {
        return reject(
          'No command string provided when calling `getCloudRequestId` action'
        );
      }

      this.set('state.rtr.isRunningCommand', true);

      const payload = {
        action: 'RUN_SCRIPT',
        sessionId,
        deviceId,
        baseCommand,
        commandString
      };

      this.sendIntegrationMessage(payload)
        .then((result) => {
          console.info(`Result from getCloudRequestId`, result);
          resolve(result);
        })
        .catch((err) => {
          reject(err);
        });
    });
  },
  getRtrResult: async function (
    cloudRequestId,
    stdout = '',
    stderr = '',
    sequenceId = 0
  ) {
    const result = await this.pollRtrResult(cloudRequestId, sequenceId);

    stdout += result.stdout;
    stderr += result.stderr;

    if (result.sessionExpired) {
      return {
        sessionExpired: true
      };
    }

    if (result.complete) {
      return {
        stdout,
        stderr
      };
    }

    // wait 2 seconds, then repeat our request
    await this.sleep(2000);
    return await this.getRtrResult(cloudRequestId, stdout, stderr, result.sequenceId);
  },
  pollRtrResult: async function (cloudRequestId, sequenceId) {
    if (!cloudRequestId) {
      throw new Error('No cloud request id provided when calling `pollRtrResult` action');
    }

    const payload = {
      action: 'GET_RTR_RESULT',
      sequenceId,
      cloudRequestId
    };

    const result = await this.sendIntegrationMessage(payload);

    return result;
  },
  sleep: async function (ms) {
    return new Promise((res) => Ember.run.later(res, ms));
  },
  /**
   *
   * @param type
   *  system -- for system messages (status, etc.)
   *  error -- for any error messages
   *  command -- any command that is issued by the user (e.g., a falconscript, ls, cd etc.)
   *  commandResult -- the result a command (e.g., ls, cd).  Commands always return formatted (pre) strings
   *  scriptResult -- the result from a script (falconscript)
   * @param value
   * String or Array content to be displayed
   * Array of objects
   * The following formats are supported which are formats returned by tested
   * Falcon Scripts
   * ```
   * [
   *   {
   *     key1: 'value1',
   *     key2: 'value2'
   *   }
   * ]
   * ```
   * or
   * ```
   *   {
   *       key1: [
   *           {
   *               subKey1: 'value1'
   *               subKey2: 'value2'
   *           },
   *           {
   *               subKey3: 'value3'
   *           }
   *       ]
   *   }
   */
  addConsoleMessage(type, value) {
    const payload = {
      type,
      value,
      isCollapsed: true
    };
    this.get('state.rtr.consoleMessages').unshiftObject(payload);
  },
  scrollToEndOfConsole() {
    const objDiv = document.getElementById(
      `crowdstrike-console-${this.get('uniqueIdPrefix')}`
    );
    objDiv.scrollTop = objDiv.scrollHeight;
  }
});
