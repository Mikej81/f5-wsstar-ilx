# ilx-idam-fakeadfs

This was created for iRulesLX on BIG-IP, for replacement of AD FS to use as a Trusted Identity Provider for SharePoint.
Modified to support multiple FQDNs and Trusted Identity Providers on a single virtual server.

There are currently 3 deployment options avaialble by switching which irule (tcl) is attached to the Virtual Servers.

* Dual Virtual Server Mode:  1 VS acts as the ADFS server and responds the way AD FS does, the other sites in front of SharePoint.
* 1 Virtual Server Mode (Standard):  Allows proxying of SharePoint through a Single VS and also impersonates, catches and responds with all appropriate tokens (Dirty Server Side SAML).
* 1 Virtual Server Mode (SmartCard):  Same as Standard, but built around supporting SmartCard attributes.

## Installation
```
  I dont have any of this set up in NPMJS yet, and probably WONT, but I will start extracting the custom moving bits and setting those up, like the WSFed Engine.

  To install, download the latest release from releases, import to your irulesLX workspaces, create a plugin, link everything up.

  Powershell script included, just replace the paths and URLs for your environment.

  Several URL's are currently hard coded in the TCL/Node so those will need to be tweaked, but everything is moving to the Config.json.

  In Single VS Mode:  Create a rewrite profile for the trusted identity provider to the Virtual Server Name, and the VS Name to SharePoint.

  See included PDF
```

May work better building from scratch in some environments.

https://devcentral.f5.com/articles/big-ip-iruleslx-fakeadfs-ws-federation-saml11-24608

## Usage
IDP initiated use-case requires a single VS, it does not require any SAML IDP or SP configurations as the initial Client Auth can be anything, the WS-Fed assertion is generated on the Server side, and posted to the Application.

For multiple VS scenarios, see included PDF.

Etensive notes are in the code.

## TODO
Working on adding Ws-Trust support.  FederationMetadata is mostly complete, endpoints currently have to be changed in federationmetadata.template, but this will be dynamic in later code updates.

## Release History
* 0.1.0 Initial release
* 0.2.0 Minor tweaks
* 0.3.0 Multiple FQDN Support added - Jeff larmore
* 0.3.1 STS Federation Metadata Support added; any endpoint ending with FederationMetadata.xml
* 0.4.0 Extensive code changes, cleanup, and other modifications to support 13.x and fix IDP/SP initiated paths.
* 0.4.2 Extensive code changes, cleanup, and other mods, trying some things out.
