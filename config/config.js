module.exports = {
  polarityIntegrationUuid: 'd4d32a30-cce1-11ed-aeee-075d3490155d',
  name: 'CrowdStrike',
  acronym: 'CSTK',
  description:
    'Displays information from relevant Crowdstrike Falcon detections based on searching behavioral indicators (process hashes, filenames) and device information (IPv4 address).',
  entityTypes: ['MD5', 'SHA256', 'IPv4', 'domain'],
  customTypes: [
    {
      key: 'exeFile',
      regex: '[\\w-]{2,}\\.(?:exe|dll|dmg|doc|pdf|csv|sh)'
    }
  ],
  onDemandOnly: true,
  defaultColor: 'light-purple',
  styles: ['./styles/crowdstrike.less'],
  block: {
    component: {
      file: './components/crowdstrike-block.js'
    },
    template: {
      file: './templates/crowdstrike-block.hbs'
    }
  },
  request: {
    cert: '',
    key: '',
    passphrase: '',
    ca: '',
    proxy: ''
  },
  logging: {
    level: 'info'
  },
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
      key: 'enableRealTimeResponse',
      name: 'Enable Real Time Response',
      description:
        'If checked, users will be able to connect to hosts and run commands, and Custom and Falcon Real Time Response scripts.',
      default: false,
      type: 'boolean',
      userCanEdit: false,
      adminOnly: false
    },
    {
      key: 'enabledCommands',
      name: 'Enabled Real Time Response Commands',
      description:
        'Comma delimited list of enabled RTR commands by command name.  Listed commands must be accessible to the configured Client ID. Command names are case-sensitive. The `Enable Real Time Response` option must be checked for this setting to have an effect. This setting must be locked for all users.',
      default: 'cat, cd, env, getsid, ipconfig, ls, netstat, ps',
      type: 'text',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'enabledFalconScripts',
      name: 'Enabled Falcon Real Time Response Scripts',
      description:
        'Comma delimited list of enabled Falcon scripts by script name.  Listed Falcon scripts must be accessible to the configured Client ID. Script names are case-sensitive. The `Enable Real Time Response` option must be checked for this setting to have an effect.  This setting must be locked for all users.',
      default:
        'LocalUser, RegisteredAV, PowerShellEnv, Monitor, LocalGroup, LastBootUpTime, FirewallRule, EventSource, EventLog, BitLocker, FileInfo, ScheduledTask, Service, SSID, Printer, NetworkShare, Process, RegistryKey, Prefetch, InstalledProgram',
      type: 'text',
      userCanEdit: false,
      adminOnly: true
    },
    {
      key: 'enabledCustomScripts',
      name: 'Enabled Custom Real Time Response Scripts',
      description:
        'Comma delimited list of enabled Custom scripts by script name. Listed Custom scripts must be accessible to the configured Client ID. Script names are case-sensitive. The `Enable Real Time Response` option must be checked for this setting to have an effect. This setting must be locked for all users.',
      default: '',
      type: 'text',
      userCanEdit: false,
      adminOnly: true
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
        },
        {
          value: 'closed',
          display: 'Closed'
        }
      ],
      multiple: true,
      userCanEdit: true,
      adminOnly: false
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
