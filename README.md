# ilx-idam-fakeadfs

This was created for iRulesLX on BIG-IP, for replacement of AD FS to use as a Trusted Identity Provider for SharePoint.  
Modified to support multiple FQDNs and Trusted Identity Providers on a single virtual server.  This is still SP initiated.

## Installation
```
  import tgz to BIG-IP - See included PDF
```
## Usage
IDP initiated use-case requires a single VS, it does not require any SAML IDP or SP configurations as the initial Client Auth can be anything, the WS-Fed assertion is generated on the Server side, and posted to the Application.

For multiple VS scenarios, see included PDF.

Etensive notes are in the code.  

## Release History

* 0.2.0 Initial release
* 0.3.0 Multiple FQDN Support added - Jeff larmore
