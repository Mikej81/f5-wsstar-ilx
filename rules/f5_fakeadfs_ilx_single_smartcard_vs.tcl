#  May require some cleaning on the SharePoint side.
#  https://docs.microsoft.com/en-us/powershell/module/sharepoint-server/Remove-SPUser?view=sharepoint-ps
#  https://docs.microsoft.com/en-us/powershell/module/sharepoint-server/New-SPUser?view=sharepoint-ps
#  going to need adjustments on the claim mappings and values passed, as needed for the environments.
#
#  Currently 'hard coded' values, so need to create dynamic logic and seperate all primitives
#

when HTTP_REQUEST {
  # save hostname for use in response
  set fqdn_name [HTTP::host]
  
    switch -glob [string tolower [HTTP::path]] {
        "*/federationmetadata/2007-06/federationmetadata.xml" {
            #Act as the STS Metadataprovider
            set fakeadfs_preapm [ILX::init f5_fakeadfs_ilx_extension]
            set issuer "https://[HTTP::host]"
            set endpoint "[HTTP::uri]"
            set metadata_response [ILX::call $fakeadfs_preapm Generate-FederationMetadata $issuer $endpoint]
            HTTP::respond 200 content $metadata_response Content-Type "application/xml"
        }
        "*/STS/Login.aspx*" {
            #Act as STS Login Provider
            #  WIF applications will do a passive redirect to STS to auth.
            #  Maybe let APM handle this landinguri.

        }
        "*adfs/services/trust/*" {
            #Act as WS-Trust Provider
            #Path can determine Auth Type, I dont want to code all of these so will have to pick a few important ones.
            #  *adfs/services/trust/*/certificate
            #  *adfs/services/trust/*/username
            #  *adfs/services/trust/*/issuedtoken*
        }
        "*/adfs/ls*" {
            log local0. ".../adfs/ls path..."
            #  Act as WS-Federation Provider
            #  Wctx: This is some session data that the application wants sent back to 
            #  it after the user authenticates.
            set wctx [URI::decode [URI::query [HTTP::uri] wctx]]
            #  Wa=signin1.0: This tells the ADFS server to invoke a login for the user.
            set wa [URI::decode [URI::query [HTTP::uri] wa]]
            #  Wtrealm: This tells ADFS what application I was trying to get to. 
            #  This has to match the identifier of one of the relying party trusts 
            #  listed in ADFS.  wtrealm is used in the Node.JS side, but we dont need it 
            #  here.

            #  Kept getting errors from APM, this fixed it.
            node 127.0.0.1    
            
            #  Make sure that the user has authenticated and APM has created a session.
            if {[HTTP::cookie exists MRHSession] } {
        
                #log local0. "Generate POST form and Autopost "
        
                #  tmpresponse is the WS-Fed Assertion data, unencoded, so straight XML
                set tmpresponse [ACCESS::session data get session.custom.idam.wsfedtoken]
        
                #  This was the pain to figure out.  The assertion has to be POSTed to 
                #  SharePoint, this was the easiest way to solve that issue.  Set timeout
                #  to half a second, but can be adjusted as needed.
                set htmltop "<html><script type='text/javascript'>window.onload=function(){ window.setTimeout(document.wsFedAuth.submit.bind(document.wsFedAuth), 500);};</script><body>"
                set htmlform "<form name='wsFedAuth' method=POST action='https://sharepoint.f5lab.com/_trust/default.aspx?trust=FakeADFS'><input type=hidden name=wa value=$wa><input type=hidden name=wresult value='$tmpresponse'><input type=hidden name=wctx value=$wctx><input type='submit' value='Continue'></form/>"
                set htmlbottom "</body></html>"
                set page "$htmltop $htmlform $htmlbottom"
                
                HTTP::respond 200 content $page
            }
        }
        default {
        #  Wctx: This is some session data that the application wants sent back to 
        #  it after the user authenticates.
        set wctx [URI::decode [URI::query [HTTP::uri] wctx]]
        #  Wa=signin1.0: This tells the ADFS server to invoke a login for the user.
        set wa [URI::decode [URI::query [HTTP::uri] wa]]
        #  Wtrealm: This tells ADFS what application I was trying to get to. 
        #  This has to match the identifier of one of the relying party trusts 
        #  listed in ADFS.  wtrealm is used in the Node.JS side, but we dont need it 
        #  here.
        
        #log local0. "Cookie: [HTTP::cookie MRHSession]"
        #log local0. "Cookie: [HTTP::cookie FedAuth]"
        #log local0. "Method: [HTTP::method]"
        #log local0. "wsFed:  [ACCESS::session data get session.custom.idam.wsfedtoken]"
        
            if {[HTTP::cookie exists MRHSession] && 
                ([HTTP::method] ne "POST") &&
                not ( [HTTP::cookie exists FedAuth] ) &&
                [ACCESS::session data get session.custom.idam.wsfedtoken] ne ""} {
                node 127.0.0.1
                
                #  tmpresponse is the WS-Fed Assertion data, unencoded, so straight XML
                set tmpresponse [ACCESS::session data get session.custom.idam.wsfedtoken]
        
                #  This was the pain to figure out.  The assertion has to be POSTed to 
                #  SharePoint, this was the easiest way to solve that issue.  Set timeout
                #  to half a second, but can be adjusted as needed.
                set currentHost [HTTP::host]
                set htmltop "<html><script type='text/javascript'>window.onload=function(){ window.setTimeout(document.wsFedAuth.submit.bind(document.wsFedAuth), 50000);};</script><body>"
                set htmlform "<form name='wsFedAuth' method=POST action='https://$currentHost/_trust/default.aspx?trust=FakeADFS'><input type=hidden name=wa value=$wa><input type=hidden name=wresult value='$tmpresponse'><input type=hidden name=wctx value=$wctx><input type='submit' value='Continue'></form/>"
                set htmlbottom "</body></html>"
                set page "$htmltop $htmlform $htmlbottom"
                
                HTTP::respond 200 content $page
                }
            }
    }
}

when ACCESS_POLICY_AGENT_EVENT {

    switch [ACCESS::policy agent_id] { 
               "ADFS" {
                   #  Create the ILX RPC Handler
                    set fakeadfs_handle [ILX::init f5_fakeadfs_plugin f5_fakeadfs_ilx_extension]
                    #  Payload is just the incoming Querystring
                    set payload [ACCESS::session data get session.server.landinguri]
                    #  Currently, the mapped attributes are Email & UPN.  In some environments,
                    #  this may match, for my use case, they will not, so there is an LDAP AAA
                    #  which is queried based on the logon name (email), and the UPN is retrieved
                    #  from LDAP.
    
                    if { [ACCESS::session data get session.custom.idam.usesmartcard] ne "true" } {
                      set AttrUserName [ACCESS::session data get session.logon.last.username]
                      set AttrUserPrin [ACCESS::session data get session.ldap.last.attr.userPrincipalName]
                      set AttrUserEmail [ACCESS::session data get session.ldap.last.attr.userPrincipalName]
                    } else {
                      set AttrUserName [ACCESS::session data get session.custom.idam.tmpcn]
                      set AttrUserPrin [ACCESS::session data get session.custom.idam.upn]
                      set AttrUserEmail [ACCESS::session data get session.custom.idam.email]
                      set AttrUserSID [ACCESS::session data get session.ldap.last.attr.objectSid]
                    }
                    log local0. "Received Process request for FakeADFS, $AttrUserName, $AttrUserPrin, $payload"
                    set wsfed_response [ILX::call $fakeadfs_handle Generate-WSFedToken $payload $AttrUserName $AttrUserPrin $AttrUserEmail $AttrUserSID]
                    ACCESS::session data set session.custom.idam.wsfedtoken $wsfed_response
               }
               "CERTPROC" {
                 ACCESS::session data set session.custom.idam.usesmartcard "true"
                 if { [ACCESS::session data get session.ssl.cert.x509extension] contains "othername:UPN<" } {
                    set tmpupn [findstr [ACCESS::session data get session.ssl.cert.x509extension] "othername:UPN<" 14 ">"]
                    ACCESS::session data set session.custom.idam.upn $tmpupn
                    log local0. "Extracted EDIPI: $tmpupn"
                 }
            if { [ACCESS::session data get session.ssl.cert.x509extension] contains "email:" } {
              set tmpemail [findstr [ACCESS::session data get session.ssl.cert.x509extension] "email:" 6 " "]
              regexp {[a-zA-Z.0-9]+@[a-zA-Z.0-9]+\.[a-zA-Z]{2,}} $tmpemail cleanemail
              ACCESS::session data set session.custom.idam.email $cleanemail
              log local0. "Extracted Email Field: $cleanemail"
            }
            if { [ACCESS::session data get session.ssl.cert.subject] contains "CN="} {
             set tmpcn [findstr [ACCESS::session data get session.ssl.cert.subject] "CN=" 3 ,]
             ACCESS::session data set session.custom.idam.tmpcn $tmpcn
             log local0. "Extracted CN: $tmpcn"
            }
            if { [ACCESS::session data get session.ssl.cert.subject] contains "C="} {
             set tmpc [findstr [ACCESS::session data get session.ssl.cert.subject] "C=" 2 ,]
             ACCESS::session data set session.custom.idam.country $tmpc
             log local0. "Extracted Country: $tmpc"
            }
            if { [ACCESS::session data get session.ssl.cert.subject] contains "O="} {
             set tmpo [findstr [ACCESS::session data get session.ssl.cert.subject] "O=" 2 ,]
             ACCESS::session data set session.custom.idam.org $tmpo
             log local0. "Extracted Org: $tmpo"
            }
            if { [ACCESS::session data get session.ssl.cert.end] ne ""} {
                set expire [ACCESS::session data get session.ssl.cert.end]
                ACCESS::session data set session.custom.idam.expiration $expire
            }
        if { [ACCESS::session data get session.ssl.cert.subject] ne ""} {
            set data [ACCESS::session data get "session.ssl.cert.subject"]
            set commonName [findstr $data "CN=" 3 ","]
            set fullcn "CN=[findstr $data "CN=" 3 "\r"]"
            log local0. "FullCN: $fullcn"
            set cert_list [split $data ","]
            scan $commonName {%[^\.].%[^\.].%[^\.].%[^\.].%[^\.]} last first middle suffix edipinum
            #log local0. "CommonName for Scan: $commonName"
            if { [info exists edipinum] } {
                log local0. "Suffix is $suffix"
                log local0. "EDIPI is $edipinum"
                ACCESS::session data set session.custom.idam.edipinum $edipinum
            } elseif { [info exists suffix] } {
            ACCESS::session data set session.custom.idam.edipinum $suffix
            log local0. "EDIPI is $suffix"
            } elseif { [info exists middle] } {
                ACCESS::session data set session.custom.idam.edipinum $middle
                log local0. "EDIPI is $middle"
            }
            ACCESS::session data set session.custom.idam.common $commonName
            #ACCESS::session data set session.custom.idam.lastname $last
            #ACCESS::session data set session.custom.idam.firstname $first
            #ACCESS::session data set session.custom.idam.sam [concat [string range $first 0 0]$last]
            #ACCESS::session data set session.custom.idam.dn "CN=$commonName,$ldap_user_dn_suffix"
            #ACCESS::session data set session.custom.idam.cn $commonName
            #ACCESS::session data set session.custom.idam.fullcn $fullcn
        }
            #CERTPROC
               }
    }
}

#  This may or may not be needed, they arent populated with actual values, but 
#  have not tested WITHOUT yet.
#
#  MSISAuth and MSISAuth1 are the encrypted cookies used to validate the SAML 
#  assertion produced for the client. These are what we call the "authentication 
#  cookies", and you will see these cookies ONLY when AD FS 2.0 is the IDP. 
#  Without these, the client will not experience SSO when AD FS 2.0 is the IDP.
#
#  MSISAuthenticated contains a base64-encoded timestamp value for when the client 
#  was authenticated. You will see this cookie set whether AD FS 2.0 is the IDP 
#  or not.
#
#  MSISSignout is used to keep track of the IDP and all RPs visited for the SSO 
#  session. This cookie is utilized when a WS-Federation sign-out is invoked. 
#  You can see the contents of this cookie using a base64 decoder.
#  MSISLoopDetectionCookie is used by the AD FS 2.0 infinite loop detection 
#  mechanism to stop clients who have ended up in an infinite redirection loop 
#  to the Federation Server. For example, if an RP is having an issue where it 
#  cannot consume the SAML assertion from AD FS, the RP may continuously redirect 
#  the client to the AD FS 2.0 server. When the redirect loop hits a certain 
#  threshold, AD FS 2.0 uses this cookie to detect that threshold being met, 
#  and will throw an exception which lands the user on the AD FS 2.0 error page 
#  rather than leaving them in the loop. The cookie data is a timestamp that is 
#  base64 encoded.
when ACCESS_ACL_ALLOWED {
    HTTP::cookie insert name "MSISAuth" value "ABCD" path "/adfs"
    HTTP::cookie insert name "MSISSignOut" value "ABCD" path "/adfs"
    HTTP::cookie insert name "MSISAuthenticated" value "ABCD" path "/adfs"
    HTTP::cookie insert name "MSISLoopDetectionCookie" value "ABCD" path "/adfs"
}

when HTTP_RESPONSE {
    HTTP::collect 32000000
    set length [HTTP::payload length]
	HTTP::header replace "Content-Length" $length
}






