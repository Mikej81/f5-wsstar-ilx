##  Create a new Trusted Root CA
$root = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("../path/to/cert")

New-SPTrustedRootAuthority -Name "Token Signing Cert Parent" -Certificate $root
##  Add Trusted Identity Provider Signing Cert
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("../path/to/cert")

##  Create all the required Claim Mappings to use
$emailClaimMap = New-SPClaimTypeMapping -IncomingClaimType "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" -IncomingClaimTypeDisplayName "EmailAddress" –SameAsIncoming

$upnClaimMap = New-SPClaimTypeMapping -IncomingClaimType "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn" -IncomingClaimTypeDisplayName "UPN" –SameAsIncoming

$roleClaimMap = New-SPClaimTypeMapping -IncomingClaimType "http://schemas.microsoft.com/ws/2008/06/identity/claims/role" -IncomingClaimTypeDisplayName "Role" –SameAsIncoming

$sidClaimMap = New-SPClaimTypeMapping -IncomingClaimType "http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid" -IncomingClaimTypeDisplayName "SID" –SameAsIncoming

##  Create the Identity Provider, generally in format of urn:sharepoint:webApp or http(s)://domain.sharepoint.domain/PATH
$realm = "urn:sharepoint:[APPName]"
## SignIn URL points the the FakeADFS / F5
$signInURL = "https://[f5domain.sharepoint.domain]/adfs/ls"

$ap = New-SPTrustedIdentityTokenIssuer -Name "[ProviderName]" -Description "[ProviderDescription]" -realm

$realm -ImportTrustCertificate $cert -ClaimsMappings $emailClaimMap,$upnClaimMap,$roleClaimMap,$sidClaimMap -SignInUrl $signInURL -IdentifierClaim $emailClaimmap.InputClaimType
