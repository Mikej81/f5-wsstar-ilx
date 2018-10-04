# f5-fakeadfs-ilx Exchange 2013 Configuration

This was created for iRulesLX on BIG-IP, for replacement of AD FS to use as a Trusted Identity Provider for Exchange.

## Installation
```
  import tgz to BIG-IP - See included PDF
```

May work better building from scratch in some environments.

https://devcentral.f5.com/articles/big-ip-iruleslx-fakeadfs-ws-federation-saml11-24608

## Usage
IDP initiated use-case requires a single VS, it does not require any SAML IDP or SP configurations as the initial Client Auth can be anything, the WS-Fed assertion is generated on the Server side, and posted to the Application.

For multiple VS scenarios, see included PDF.

Etensive notes are in the code.

## Prerequisites
Exchange requires two attribute in the claim, Active Directory User SID (objectSid), ActiveDirectory UPN (userPrincipalName).  These are already exposed as assertion attributes in the ILX and TCL portions of the code, it will be important to make sure they are populated.

You will need the thumbprint of the certificate used by "fakeadfs" for token-signing.  View the certificate loaded in the workspace and copy the thumbnail value, removing any spaces.

It is recommended that you are using Exchange 2013 SP1 with AT LEAST CU21 installed.

## Exchange Config
Adjust the following to match your FQDN/URIs and Thumbprint acquired previously.  Be careful setting the ecp/owa authenticatio, if the thumbprint or endpoints dont match, you wont be able to log in to ECA or OWA, but you will be able to fix things with powershell.

```
$uris = @("https://domain.com/owa/", "https://domain.com/owa", "https://mail.contoso.com/ecp/", "https://domain.com/ecp")
Set-OrganizationConfig -AdfsIssuer "https://fakeadfs.domain.com/adfs/ls/" -AdfsAudienceUris $uris -AdfsSignCertificateThumbprint 88970C64278A15D642934DC2961D9CCA5E28DA6B

Get-EcpVirtualDirectory | Set-EcpVirtualDirectory -AdfsAuthentication $true -BasicAuthentication $false
-DigestAuthentication $false -FormsAuthentication $false -WindowsAuthentication $false

Get-OwaVirtualDirectory | Set-OwaVirtualDirectory -AdfsAuthentication $true -BasicAuthentication $false
-DigestAuthentication $false -FormsAuthentication $false -WindowsAuthentication $false

Restart-Service W3SVC,WAS
```
* Reference:  https://technet.microsoft.com/library/dn635116(v=exchg.150).aspx

## APM Configuration
Most of the configs should match the sharepoint guidance.  You want to ensure that you are quering for the extra fields if they are not available in your MFA tokens.  As mentioned previously concerning claims, the attributes are userPrincipalName and objectSid.

## TODO
Working on adding Ws-Trust support.  FederationMetadata is mostly complete, endpoints currently have to be changed in federationmetadata.template, but this will be dynamic in later code updates.

## Release History
* 0.1.0 Initial release
* 0.2.0 Minor tweaks
* 0.3.0 Multiple FQDN Support added - Jeff larmore
* 0.3.1 STS Federation Metadata Support added; any endpoint ending with FederationMetadata.xml
* 0.4.0 Extensive code changes, cleanup, and other modifications to support 13.x and fix IDP/SP initiated paths.
