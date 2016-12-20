when HTTP_REQUEST {
    set wctx [URI::decode [URI::query [HTTP::uri] wctx]]
    set wa [URI::decode [URI::query [HTTP::uri] wa]]

    node 127.0.0.1
    
        if {[HTTP::cookie exists MRHSession]} {
        log local0. "Generate POST form and Autopost "

        set tmpuri [URI::encode [ACCESS::session data get session.custom.idam.response]]
        set tmpresponse [ACCESS::session data get session.custom.idam.response]
        
        set htmltop "<html><script type='text/javascript'>window.onload=function(){ window.setTimeout(document.wsFedAuth.submit.bind(document.wsFedAuth), 500);};</script><body>"
        set htmlform "<form name='wsFedAuth' method=POST action='https://sharepoint.f5lab.com/_trust/'><input type=hidden name=wa value=$wa><input type=hidden name=wresult value='$tmpresponse'><input type=hidden name=wctx value=$wctx><input type='submit' value='Continue'></form/>"
        set htmlbottom "</body></html>"
        set page "$htmltop $htmlform $htmlbottom"
        
        HTTP::respond 200 content $page
    
        }

}

when ACCESS_POLICY_AGENT_EVENT {
    set fakeadfs_handle [ILX::init fakeadfs_extension]
    set payload [ACCESS::session data get session.server.landinguri]
    set AttrUserName [ACCESS::session data get session.logon.last.username]
    set AttrUserPrin [ACCESS::session data get session.ldap.last.attr.userPrincipalName ]

    switch [ACCESS::policy agent_id] { 
               "ADFS" {
                    log local0. "Received Process request for FakeADFS, $payload"
                    set fakeadfs_response [ILX::call $fakeadfs_handle Generate-WSFedToken $payload $AttrUserName $AttrUserPrin]
                    ACCESS::session data set session.custom.idam.response $fakeadfs_response  
               }
    }
}

when ACCESS_ACL_ALLOWED {
    HTTP::cookie insert name "MSISAuth" value "ABCD" path "/adfs"
    HTTP::cookie insert name "MSISSignOut" value "ABCD" path "/adfs"
    HTTP::cookie insert name "MSISAuthenticated" value "ABCD" path "/adfs"
    HTTP::cookie insert name "MSISLoopDetectionCookie" value "ABCD" path "/adfs"
    
}
