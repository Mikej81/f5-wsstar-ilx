
/* Import the f5-nodejs module. */
var f5 = require('f5-nodejs');

var saml11 = require('saml').Saml11;
var queryString = require('querystring');
var fs = require('fs');
var moment = require('moment');
var https = require('https');

var timeout = 3600;
var wsfedIssuer = "http://fakeadfs.f5lab.com/adfs/services/trust";
var SigningCert = "/fakeadfs.f5lab.com.crt";
var SigningKey = "/fakeadfs.f5lab.com.key";

/* Create a new rpc server for listening to TCL iRule calls. */
var ilx = new f5.ILXServer();

ilx.addMethod('Generate-WSFedToken', function(req,res) {
    var query = queryString.unescape(req.params()[0]);
    var queryOptions = queryString.parse(query);
    var AttrUserName = req.params()[1];
    var AttrUserPrincipal = req.params()[2];
     
    var wa = queryOptions.wa;
    var wtrealm = queryOptions.wtrealm;
    var wctx = queryOptions.wctx;
    
    var now = moment.utc();
    var wsfed_wrapper_head = "<t:RequestSecurityTokenResponse xmlns:t=\"http://schemas.xmlsoap.org/ws/2005/02/trust\">";
     wsfed_wrapper_head += "<t:Lifetime><wsu:Created xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">" + now.format('YYYY-MM-DDTHH:mm:ss.SSS[Z]') +"</wsu:Created>";
     wsfed_wrapper_head += "<wsu:Expires xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">" + now.add(timeout, 'seconds').format('YYYY-MM-DDTHH:mm:ss.SSS[Z]') + "</wsu:Expires>";
     wsfed_wrapper_head += "</t:Lifetime><wsp:AppliesTo xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\"><wsa:EndpointReference xmlns:wsa=\"http://www.w3.org/2005/08/addressing\">";
     wsfed_wrapper_head += "<wsa:Address>" + wtrealm + "</wsa:Address>";
     wsfed_wrapper_head += "</wsa:EndpointReference></wsp:AppliesTo><t:RequestedSecurityToken>";
    
    //Now insert the SAML11 Assertion
    var saml11_options = {
        cert: fs.readFileSync(__dirname + SigningCert),
        key: fs.readFileSync(__dirname + SigningKey),
        issuer: wsfedIssuer,
        lifetimeInSeconds: timeout,
        audiences: wtrealm,
        attributes: {
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress':  AttrUserName  ,
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn': AttrUserPrincipal
        }
    };
    
    var signedAssertion = saml11.create(saml11_options);
    
    var wsfed_wrapper_foot = "</t:RequestedSecurityToken><t:TokenType>urn:oasis:names:tc:SAML:1.0:assertion</t:TokenType><t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType><t:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</t:KeyType></t:RequestSecurityTokenResponse>";
    			
    var wresult = wsfed_wrapper_head + signedAssertion + wsfed_wrapper_foot;

    var qencoded = wresult;
    
    res.reply(qencoded);
});


/* Start listening for ILX::call and ILX::notify events. */
ilx.listen();

