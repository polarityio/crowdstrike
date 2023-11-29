module.exports = {
  /**
   * Name of the integration which is displayed in the Polarity integrations user interface
   *
   * @type String
   * @required
   */
  name: 'CrowdStrike',
  /**
   * The acronym that appears in the notification window when information from this integration
   * is displayed.  Note that the acronym is included as part of each "tag" in the summary information
   * for the integration.  As a result, it is best to keep it to 4 or less characters.  The casing used
   * here will be carried forward into the notification window.
   *
   * @type String
   * @required
   */
  acronym: 'CSTK',
  /**
   * Description for this integration which is displayed in the Polarity integrations user interface
   *
   * @type String
   * @optional
   */
  description:
    'Displays information from relevant Crowdstrike Falcon detections based on searching behavioral indicators (process hashes, filenames) and device information (IPv4 address).',
  entityTypes: ['md5', 'sha256', 'IPv4', 'domain'],
  customTypes: [
    {
      key: 'exeFile',
      regex: /[\w-]{2,}\.(?:exe|dll|dmg|doc|pdf|csv|sh)/
    }
    // {
    //   key: 'hostname',
    //   regex: /DESKTOP\-[A-Za-z0-9]*/
    // }
  ],
  onDemandOnly: true,
  defaultColor: 'light-purple',
  /**
   * An array of style files (css or less) that will be included for your integration. Any styles specified in
   * the below files can be used in your custom template.
   *
   * @type Array
   * @optional
   */
  styles: ['./styles/crowdstrike.less'],
  /**
   * Provide custom component logic and template for rendering the integration details block.  If you do not
   * provide a custom template and/or component then the integration will display data as a table of key value
   * pairs.
   *
   * @type Object
   * @optional
   */
  block: {
    component: {
      file: './components/crowdstrike-block.js'
    },
    template: {
      file: './templates/crowdstrike-block.hbs'
    }
  },
  request: {
    // Provide the path to your certFile. Leave an empty string to ignore this option.
    // Relative paths are relative to the integration's root directory
    cert: '',
    // Provide the path to your private key. Leave an empty string to ignore this option.
    // Relative paths are relative to the integration's root directory
    key: '',
    // Provide the key passphrase if required.  Leave an empty string to ignore this option.
    // Relative paths are relative to the integration's root directory
    passphrase: '',
    // Provide the Certificate Authority. Leave an empty string to ignore this option.
    // Relative paths are relative to the integration's root directory
    ca: '',
    // An HTTP proxy to be used. Supports proxy Auth with Basic Auth, identical to support for
    // the url parameter (by embedding the auth info in the uri)
    proxy: ''
  },
  logging: {
    // directory is relative to the this integrations directory
    // e.g., if the integration is in /app/polarity-server/integrations/virustotal
    // and you set directoryPath to be `integration-logs` then your logs will go to
    // `/app/polarity-server/integrations/integration-logs`
    // You can also set an absolute path.  If you set an absolute path you must ensure that
    // the directory you specify is writable by the `polarityd:polarityd` user and group.

    //directoryPath: '/var/log/polarity-integrations',
    level: 'info' //trace, debug, info, warn, error, fatal
  },
  /**
   * Options that are displayed to the user/admin in the Polarity integration user-interface.  Should be structured
   * as an array of option objects.
   *
   * @type Array
   * @optional
   */
  options: [
    {
      key: 'url',
      name: 'CrowdStrike API URL',
      description:
        'The REST API URL for your CrowdStrike instance which should include the schema (i.e., http, https) and port if required.',
      default: 'https://api.crowdstrike.com',
      type: 'text',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'uiUrl',
      name: 'CrowdStrike UI URL',
      description: 'The URL for your CrowdStrike UI instance',
      default: 'https://falcon.crowdstrike.com',
      type: 'text',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'id',
      name: 'Client ID',
      description: 'The Client ID to use to connect to CrowdStrike.',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'secret',
      name: 'Client Secret',
      description:
        "The secret associated with the Client ID. At a minimum, the API key must have 'Read' access to the 'Detections' scope.",
      default: '',
      type: 'password',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'searchIoc',
      name: 'Search CrowdStrike IOCs',
      description:
        "If checked, the integration will search IOCs detected in your environment.  IOCs (indicators of compromise) are artifacts that include SHA256, MD5 or domain values.  The provided API key must have 'Read' access to the 'IOC Manager APIs' scope for this option to work.",
      default: true,
      type: 'boolean',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'allowContainment',
      name: 'Allow Containment Status Change',
      description:
        "If checked, users will be able to change the Containment Status of Devices via the integration.  The provided API key must have 'Read' and 'Write' access to the 'Hosts' scope for this option to work.  This option must be set to \"Users can view only\".",
      default: false,
      type: 'boolean',
      userCanEdit: false,
      adminOnly: false
    },
    {
      key: 'minimumSeverity',
      name: 'Minimum Severity for Detections',
      description:
        "The minimum severity level required for Detections to be displayed.  Defaults to 'Low'.",
      default: {
        value: 'Low',
        display: 'Low'
      },
      type: 'select',
      options: [
        {
          value: 'Low',
          display: 'Low'
        },
        {
          value: 'Medium',
          display: 'Medium'
        },
        {
          value: 'High',
          display: 'High'
        },
        {
          value: 'Critical',
          display: 'Critical'
        }
      ],
      multiple: false,
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'detectionStatuses',
      name: 'Detection Statuses',
      description: 'Detection statuses you would like to return results for.',
      default: [
        {
          value: 'new',
          display: 'New'
        },
        {
          value: 'in_progress',
          display: 'In Progress'
        },
        {
          value: 'true_positive',
          display: 'True Positive'
        }
      ],
      type: 'select',
      options: [
        {
          value: 'in_progress',
          display: 'In Progress'
        },
        {
          value: 'true_positive',
          display: 'True Positive'
        },
        {
          value: 'false_positive',
          display: 'False Positive'
        },
        {
          value: 'ignored',
          display: 'Ignored'
        },
        {
          value: 'new',
          display: 'New'
        }
      ],
      multiple: true,
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: 'showNoResults',
      name: 'Show No Results',
      description:
        'If checked, the integration will return a summary tag indicating a lookup was performed and that there are no results.',
      default: true,
      type: 'boolean',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'maxConcurrent',
      name: 'Max Concurrent Requests',
      description:
        'Maximum number of concurrent requests.  Integration must be restarted after changing this option. Defaults to 20.',
      default: 20,
      type: 'number',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'minTime',
      name: 'Minimum Time Between Lookups',
      description:
        'Minimum amount of time in milliseconds between lookups. Integration must be restarted after changing this option. Defaults to 100.',
      default: 100,
      type: 'number',
      userCanEdit: false,
      adminOnly: true
    }
  ]
};
