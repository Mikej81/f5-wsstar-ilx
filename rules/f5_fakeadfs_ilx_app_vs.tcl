when ACCESS_ACL_ALLOWED {
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
    #  You can see the contents of this cookie using a base64 decoder
    #
    #  MSISLoopDetectionCookie is used by the AD FS 2.0 infinite loop detection 
    #  mechanism to stop clients who have ended up in an infinite redirection loop 
    #  to the Federation Server. For example, if an RP is having an issue where it 
    #  cannot consume the SAML assertion from AD FS, the RP may continuously redirect 
    #  the client to the AD FS 2.0 server. When the redirect loop hits a certain 
    #  threshold, AD FS 2.0 uses this cookie to detect that threshold being met, 
    #  and will throw an exception which lands the user on the AD FS 2.0 error page 
    #  rather than leaving them in the loop. The cookie data is a timestamp that is 
    #  base64 encoded.
    HTTP::cookie insert name "MSISAuth" value "ABCD" path "/adfs"
    HTTP::cookie insert name "MSISSignOut" value "ABCD" path "/adfs"
    HTTP::cookie insert name "MSISAuthenticated" value "ABCD" path "/adfs"
    HTTP::cookie insert name "MSISLoopDetectionCookie" value "ABCD" path "/adfs"
    
}

