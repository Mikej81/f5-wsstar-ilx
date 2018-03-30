when HTTP_REQUEST {
    
    # Set adfsdebug to 1 for logging to LTM log. 0 for no logging.
	set adfsdebug 0
		
	# Check for the /adfs/ls URI.  If it doesn't start with that it is not an ADFS request
	switch -glob [HTTP::uri] {
	  "/adfs/ls*" {
	
	    if { $adfsdebug } { log local0. "HTTP_REQUEST - URI Starts with /adfs/ls"}
	
		#  Wctx: This is some session data that the application wants sent back to 
		#  it after the user authenticates. i.e. wctx=https://sp_kerb.lab.local/_layouts/15/Authenticate.aspx?Source=%2F
		set wctx [URI::decode [URI::query [HTTP::uri] wctx]]
		
		#  Wa=signin1.0: This tells the ADFS server to invoke a login for the user.
		set wa [URI::decode [URI::query [HTTP::uri] wa]]

		#  Wtrealm: This tells ADFS what application I was trying to get to. 
		#  This has to match the identifier of one of the relying party trusts 
		#  listed in ADFS.  wtrealm is used in the Node.JS side, but we dont need it 
		#  here.  i.e. wtrealm=urn:app1:
		set wtrealm [URI::decode [URI::query [HTTP::uri] wtrealm]]
		
		#  Pull the FQDN out of the wctx field to use for the redirect and post later
		#  Since wctx is in the pattern https://fqdn/uri split on the / and grab the third field.
		set referfqdn [getfield $wctx "/" 3]

		#  Kept getting errors from APM, this fixed it.
		node 127.0.0.1    
		
		if { $adfsdebug } { log local0. "HTTP_REQUEST"}
		if { $adfsdebug } { log local0. "wctx= $wctx"}
		if { $adfsdebug } { log local0. "wa= $wa"}
		if { $adfsdebug } { log local0. "wtrealm= $wtrealm"}
		if { $adfsdebug } { log local0. "referfqdn= $referfqdn"}
		
		#  Make sure that the user has authenticated and APM has created a session.
		if {[HTTP::cookie exists MRHSession]} {
            if { $adfsdebug } { log local0. "MRHSession Cookie Exists"}
            if { $adfsdebug } { log local0. "LandingURI: [ACCESS::session data get session.server.landinguri]"}
            if { $adfsdebug } { log local0. "HTTP URI: [HTTP::uri]"}
			
			#  Create the ILX RPC Handler
			set fakeadfs_handle [ILX::init fakeadfs_extension]
			#  Payload is just the incoming Querystring
			#set payload [ACCESS::session data get session.server.landinguri]
			set payload [HTTP::uri]
			
			#  There is an LDAP AAA which is queried based on the certificate UPN 
			#  and the rest of the attributes are retrieved from LDAP.
			set AttrSurName [ACCESS::session data get session.ldap.last.attr.sn]
			set AttrGivenName [ACCESS::session data get session.ldap.last.attr.givenName]
			set AttrEmailAddress [ACCESS::session data get session.ldap.last.attr.mail]
			set AttrDisplayName [ACCESS::session data get session.ldap.last.attr.displayName]
			set AttrUserPrin [ACCESS::session data get session.ldap.last.attr.userPrincipalName ]

            if { $adfsdebug } { 
                log local0. "____________________________"
                log local0. "Received Process request for FakeADFS, $payload"
                log local0. "AttrSurName= $AttrSurName"
                log local0. "AttrGivenName= $AttrGivenName"
                log local0. "AttrEmailAddress= $AttrEmailAddress"
                log local0. "AttrDisplayName= $AttrDisplayName"
                log local0. "AttrUserPrin= $AttrUserPrin"
                log local0. "____________________________"
            }

			#  Current solution uses Node.JS SAML module and can support SAML11, as well
			#  as SAML20.  Call iRulesLX which generates the token
			#  based on the submitted QueryString and the logon attributed.
			set fakeadfs_response [ILX::call $fakeadfs_handle Generate-WSFedToken $payload $AttrSurName $AttrUserPrin $AttrGivenName $AttrEmailAddress $AttrDisplayName]
			ACCESS::session data set session.custom.idam.response $fakeadfs_response  
			
			if { $adfsdebug } {log local0. "ADFS_RESPONSE: $fakeadfs_response"}
			if { $adfsdebug } { log local0. "Generate POST form and Autopost "}

			#  tmpresponse is the WS-Fed Assertion data, unencoded, so straight XML
			set tmpresponse [ACCESS::session data get session.custom.idam.response]

			#  The assertion has to be POSTed to SharePoint.
			#  Set timeout to half a second, but can be adjusted as needed.
			
			# Original code that displayed a Continue button that does nothing
			#set htmltop "<html><script type='text/javascript'>window.onload=function(){ window.setTimeout(document.wsFedAuth.submit.bind(document.wsFedAuth), 500);};</script><body>"
			#set htmlform "<form name='wsFedAuth' method=POST action='https://$referfqdn/_trust/default.aspx?trust=F5ADFS'><input type=hidden name=wa value=$wa><input type=hidden name=wresult value='$tmpresponse'><input type=hidden name=wctx value=$wctx><input type='submit' value='Procession Authentication'></form/>"
			#set htmlbottom "</body></html>"
			#set page "$htmltop $htmlform $htmlbottom"
			
			# Modified to display a page with picture instead
			set htmltop "<html><script type='text/javascript'>window.onload=function(){ window.setTimeout(document.wsFedAuth.submit.bind(document.wsFedAuth), 500);};</script><head><meta name='viewport' content='width=device-width'></head><body style='margin: 0px;'>"
			set htmlform "<form name='wsFedAuth' method=POST action='https://$referfqdn/_trust/default.aspx?trust=F5ADFS'><input type=hidden name=wa value=$wa><input type=hidden name=wresult value='$tmpresponse'><input type=hidden name=wctx value=$wctx></form/>"
			set htmlbottom "<video loop fullscreen autoplay name='media'><source src='movie.mp4' type='video/mp4'></video></body></html>"

            if { $adfsdebug } { 
                log local0. "____________________________"
                log local0. "htmltop = $htmltop"
                log local0. "htmlbottom = $htmlbottom"
            }


			set page "$htmltop $htmlform $htmlbottom"

			HTTP::respond 200 content $page
			if { $adfsdebug } { log local0. "POST Sent to Browser"}
			#HTTP::respond 200 content [subst -nocommands -nobackslashes [ifile get movie.htm]]
		} else {
			if { $adfsdebug } { log local0. "No MHRSession"}
		}
	  }
	"/adfs/movie.mp4" {
	    HTTP::respond 200 content [ifile get movie.mp4]
	    if { $adfsdebug } { log local0. "Video Sent to Browser"}
      }
    default {
    	#########################
	    # Was not an ADFS Request
    	#########################
    	if { $adfsdebug } { log local0. "URI did not start with /adfs/ls.  URI = [HTTP::uri]"}
    	HTTP::respond 200 content "Incorrectly formated ADFS request.  Open SharePoint page first."
	  }
	}
}
