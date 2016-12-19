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
        log local0. "Generate POST form and Autopost "
        #log local0. "[ACCESS::session data get session.custom.idam.response]"
        set tmpuri [URI::encode [ACCESS::session data get session.custom.idam.response]]
        set tmpresponse [ACCESS::session data get session.custom.idam.response]
        
        #HTTP::respond 307 Location $referal$tmpuri
        set html "<html><script type=\"text/javascript\">window.onload=function(){ window.setTimeout(document.wsFedAuth.submit.bind(document.wsFedAuth), 5000);};</script><body>"
        set form "<form name=\"wsFedAuth\" method=POST action=\"https://sharepoint.f5lab.com\"><input type=hidden name=wa value=wsignin1.0>"
        set wresult "<input type=hidden name=wresult value=\"$tmpresponse\">"
        set closeform "<input type=\"submit\" value=\"Continue\"></form/></body></html>"
        log local0. "Site: $html$closeform"
        HTTP::respond 200 Content "$html $form $closeform"
    
        }

}
when HTTP_RESPONSE {

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








