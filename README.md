# Polarity Crowdstrike Integration

![image](https://img.shields.io/badge/status-beta-green.svg)


## Creating a Client ID / Client Secret

Before using the Polarity Crowdstrike Integration you will need to create a Client ID and Client Secret to connect to Crowdstrike with.  The following steps will guide you through the process:

1. Log onto the Crowdstrike Falcon console.
2. Go to `Support > API Client and Keys`.
3. Click `Add New API Client`.
4. A dialog will appear, enter the name of the integration (e.g. `Polarity`) and a description (optional).
5. Polarity will need `Read` access to both `Containment` and `Detection`, so make sure to click both checkboxes. 
6. Click `Add`. Record the Client ID and Client Secret (Client secret will only be shown once for security purpose, so make sure to store it in a secure place).

Use the Client ID and Client Secret that you recorded previously to fill out the integration options. You are now ready to use the Polarity integration with Crowdstrike!

## crowdstrike Integration Options

### Client ID

The Client ID to use to connect to Crowdstrike.

### Client Secret

The secret associated with the Client ID.

### Lookup Detects

Lookup detects when an entity is matched by Polarity.

### Lookup Devices

Lookup devices when an entity is matched by Polarity. WARNING: This operation can be expensive and make a lot of API calls so it is disabled by default.

### Lookup Device Count

Lookup device count when an entity is matched by Polarity.

### Lookup IOCs

Lookup IOCs when an entity is matched by Polarity.

## Polarity

Polarity is a memory-augmentation platform that improves and accelerates analyst decision making.  For more information about the Polarity platform please see: 

https://polarity.io/
