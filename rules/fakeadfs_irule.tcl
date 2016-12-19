when HTTP_REQUEST {
#HTTP::header insert "clientless-mode" 1
#if {[HTTP::method] eq "GET"}{
    set referal [URI::decode [URI::query [HTTP::uri] wctx]]
    #set payload [URI::query [HTTP::uri]]
    
    #set fakeadfs_handle [ILX::init fakeadfs_extension]
    #set fakeadfs_response [ILX::call $fakeadfs_handle Generate-WSFedToken $payload]
    
    #HTTP::respond 200 content "$referal&wa=wsignin1.0&wresult=$fakeadfs_response&wctx=https://sharepoint.f5lab.com/_layouts/15/Authenticate.aspx?Source=%2F"
    #HTTP::respond 302 Location $fakeadfs_response
    #}
    node 127.0.0.1
    
        if {[HTTP::cookie exists MRHSession]} {
        log local0. "Redirect that MOFO: "
        #log local0. "[ACCESS::session data get session.custom.idam.response]"
        set tmpuri [URI::encode [ACCESS::session data get session.custom.idam.response]]
        
        HTTP::respond 307 Location $referal$tmpuri
    
        }

}
when HTTP_RESPONSE {
    #HTTP::respond 200 Content "<html><body>HTTP_RESPONSE<body></html>"
    #if {[HTTP::cookie exists MRHSession]} {
    #    log local0. "Redirect that MOFO: "
    #    log local0. "[ACCESS::session data get session.custom.idam.response]"
    #    HTTP::respond 302 Location [ACCESS::session data get session.custom.idam.response]
    #}
}

when ACCESS_POLICY_AGENT_EVENT {
    set fakeadfs_handle [ILX::init fakeadfs_extension]
    set payload [ACCESS::session data get session.server.landinguri]
    switch [ACCESS::policy agent_id] { 
               "ADFS" {
                    log local0. "Received Process request for FakeADFS, $payload"
                    set fakeadfs_response [ILX::call $fakeadfs_handle Generate-WSFedToken $payload]
                    ACCESS::session data set session.custom.idam.response $fakeadfs_response  
               }
    }
}

when ACCESS_ACL_ALLOWED {
    HTTP::cookie insert name "MSISAuth" value "ABCD" path "/adfs"
    HTTP::cookie insert name "MSISSignOut" value "ABCD" path "/adfs"
    HTTP::cookie insert name "MSISAuthenticated" value "ABCD" path "/adfs"
    HTTP::cookie insert name "MSISLoopDetectionCookie" value "ABCD" path "/adfs"
    
    log local0. "RESPONSE=====================================" 
    foreach aHeader [HTTP::header names] { 
        log local0. "$aHeader: [HTTP::header value $aHeader]" 
    } 
    log local0. "============================================="
    
}






