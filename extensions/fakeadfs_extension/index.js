/* iRulesLX FakeADFS, Michael Coleman
   Michael@f5.com
   */
/* Import the f5-nodejs module. */
var f5 = require('f5-nodejs');

/* Import the additional Node.JS Modules
   If from scratch:
   npm install saml
   npm install querystring
   npm install fs 
   npm install moment 
   npm install https
   
   If importing the ILX Workspace:
   npm update
   
   When the saml module is loaded, edit the saml11.template under /lib/
   to resemble the following:
   
   <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" MajorVersion="1" MinorVersion="1" AssertionID="" IssueInstant="">
  <saml:Conditions>
    <saml:AudienceRestrictionCondition />
  </saml:Conditions>
  <saml:AttributeStatement>
    <saml:Subject>
      <saml:SubjectConfirmation>
        <saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:ConfirmationMethod>
      </saml:SubjectConfirmation>
    </saml:Subject>
  </saml:AttributeStatement>
  <saml:AuthenticationStatement 
      AuthenticationMethod="urn:oasis:names:tc:SAML:1.0:am:password">
    <saml:Subject>
       <saml:SubjectConfirmation>
          <saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:ConfirmationMethod>
       </saml:SubjectConfirmation>
    </saml:Subject>
  </saml:AuthenticationStatement>
</saml:Assertion>
*/

var saml11 = require('saml').Saml11;
var queryString = require('querystring');
var fs = require('fs');
var moment = require('moment');
var https = require('https');

/*  timeout is the length of time for the assertion validity
    wsfedIssuer is, believe it or not, the Issuer
    SigningCert, SigningKey are the required certificate and key pair
     for signing the assertion and specifically the DigestValue.
*/
var timeout = 3600;
var wsfedIssuer = "http://fakeadfs.f5lab.com/adfs/services/trust";
var SigningCertpath = "/fakeadfs.f5lab.com.crt";
var SigningKeypath = "/fakeadfs.f5lab.com.key";

var SigningCert = fs.readFileSync(__dirname +SigningCertpath);
var SigningKey = fs.readFileSync(__dirname +SigningKeypath);

/* These are for IDP initated SSO requets, since the Querystring will be
   blank.
   */
var idp_wa = "signin1.0";
var idp_wtrealm = "urn:sharepoint:f5lab";
var idp_wctx = "https://sharepoint.f5lab.com/_layouts/15/Authenticate.aspx?Source=%2F";

/*
  Some Attribute Mapping Claims Options
  Source:  https://technet.microsoft.com/en-us/library/ee913589(v=ws.11).aspx
  
  http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress
  http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn
  http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname
*/


/* Create a new rpc server for listening to TCL iRule calls. */
var ilx = new f5.ILXServer();

ilx.addMethod('Generate-WSFedToken', function(req,res) {
    /* Extract the ILX parameters to add to the Assertion data
       req.params()[0] is the first passed argument
       req.params()[1] is the second passed argument, and so on.
    */
    var query = queryString.unescape(req.params()[0]);
    var queryOptions = queryString.parse(query);
    var AttrUserName = req.params()[1];
    var AttrUserPrincipal = req.params()[2];
    
    /* If incoming request is IDP initiated, the Querystrings will not 
       be populated, so lets check, and if undefined, populate with static
       IDP config vars.
       */ 
    var wa = queryOptions.wa;
    if (typeof wa == 'undefined') {
        wa = idp_wa;
    }
    var wtrealm = queryOptions.wtrealm;
    if (typeof wtrealm == 'undefined') {
        wtrealm = idp_wtrealm;
    }
    var wctx = queryOptions.wctx;
    if (typeof wctx == 'undefined') {
        wctx = idp_wctx;
    }
    
    console.log("wa=" + wa + ", wtrealm=" + wtrealm + ", wctx=" + wctx);
    
    /* This is where the WS-Fed gibberish is assembled.  Moment is required to 
       insert the properly formatted time stamps.*/
    var now = moment.utc();
    var wsfed_wrapper_head = "<t:RequestSecurityTokenResponse xmlns:t=\"http://schemas.xmlsoap.org/ws/2005/02/trust\">";
     wsfed_wrapper_head += "<t:Lifetime><wsu:Created xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">" + now.format('YYYY-MM-DDTHH:mm:ss.SSS[Z]') +"</wsu:Created>";
     wsfed_wrapper_head += "<wsu:Expires xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">" + now.add(timeout, 'seconds').format('YYYY-MM-DDTHH:mm:ss.SSS[Z]') + "</wsu:Expires>";
     wsfed_wrapper_head += "</t:Lifetime><wsp:AppliesTo xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\"><wsa:EndpointReference xmlns:wsa=\"http://www.w3.org/2005/08/addressing\">";
     wsfed_wrapper_head += "<wsa:Address>" + wtrealm + "</wsa:Address>";
     wsfed_wrapper_head += "</wsa:EndpointReference></wsp:AppliesTo><t:RequestedSecurityToken>";
    
    /* Generate and insert the SAML11 Assertion.  These attributed are 
       configured previously in the code.
       
       cert: this is the cert used for encryption
       key: this is the key used for the cert
       issuer: the assertion issuer 
       lifetimeInSeconds: timeout
       audiences: this is the application ID for sharepoint, urn:sharepoint:webapp
       attributes:  these should map to the mappings created for the IDP in SharePoint
       */
    var saml11_options = {
        cert: SigningCert,
        key: SigningKey,
        issuer: wsfedIssuer,
        lifetimeInSeconds: timeout,
        audiences: wtrealm,
        attributes: {
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress':  AttrUserName  ,
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn': AttrUserPrincipal
        }
    };
    
    /* Sign the Assertion */
    var signedAssertion = saml11.create(saml11_options);
    
    /* Add the WS-Fed footer */
    var wsfed_wrapper_foot = "</t:RequestedSecurityToken><t:TokenType>urn:oasis:names:tc:SAML:1.0:assertion</t:TokenType><t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType><t:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</t:KeyType></t:RequestSecurityTokenResponse>";
    /* Put them all together */			
    var wresult = wsfed_wrapper_head + signedAssertion + wsfed_wrapper_foot;
    /* respond back to TCL with the complete assertion */
    res.reply(wresult);
});


/* Start listening for ILX::call and ILX::notify events. */
ilx.listen();





