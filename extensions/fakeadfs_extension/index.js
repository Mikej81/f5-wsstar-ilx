
/* Import the f5-nodejs module. */
var f5 = require('f5-nodejs');

var saml11 = require('saml').Saml11;
var queryString = require('querystring');
var crypto = require('crypto');
var fs = require('fs');
var moment = require('moment');
var https = require('https');

var timeout = 3600;
var wsfedIssuer = "http://fakeadfs.f5lab.com/adfs/services/trust";

//This is unsecure (rejectUnauthorized), use CA option instead for future versions
var post_options = {
    rejectUnauthorized: false,
    hostname: 'sharepoint.f5lab.com',
    port: 443,
    path: '/_trust/default.aspx?trust=FakeADFS&amp;ReturnUrl=%2f_layouts%2f15%2fAuthenticate.aspx%3fSource%3d%252F&amp;Source=%2f',
    method: 'POST',
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
};


/* Create a new rpc server for listening to TCL iRule calls. */
var ilx = new f5.ILXServer();

ilx.addMethod('Generate-WSFedToken', function(req,res) {
    var query = queryString.unescape(req.params());
    var queryOptions = queryString.parse(query);
     
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
        cert: fs.readFileSync(__dirname + '/fakeadfs.f5lab.com.crt'),
        key: fs.readFileSync(__dirname + '/fakeadfs.f5lab.com.key'),
        issuer: 'http://fakeadfs.f5lab.com/adfs/services/trust',
        lifetimeInSeconds: timeout,
        audiences: wtrealm,
        attributes: {
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': 'mcoleman@f5lab.com',
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn': '0867530901@f5lab.com'
        }
    };
    
    var signedAssertion = saml11.create(saml11_options);
    
    var wsfed_wrapper_foot = "</t:RequestedSecurityToken><t:TokenType>urn:oasis:names:tc:SAML:1.0:assertion</t:TokenType><t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType><t:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</t:KeyType></t:RequestSecurityTokenResponse>";
    			
    var wresult = "wa=wsignin1.0&amp;wresult=";
     wresult += wsfed_wrapper_head + signedAssertion + wsfed_wrapper_foot;
     wresult += "&wctx=https://sharepoint.f5lab.com/_layouts/15/Authenticate.aspx?Source=%2F";
    
    //var qencoded = encodeURI(wresult);
    var qencoded = wresult;
    
    /*var auth_post = https.request(post_options, function(authres) {
     *   console.log("statusCode: ", authres.statusCode);
     *   console.log("statusMess: ", authres.statusMessage);
     *   console.log("headers: ", authres.headers);

     *   authres.on('data', function(d) {
     *       process.stdout.write(d);
     *   });
    *});
    *auth_post.write(qencoded);
    *auth_post.end();
    */
    
    res.reply(qencoded);
});

/*
 * ilx.addMethod('<REMOTE_FUNC_NAME>', function(req, res) {
 *   // Function parameters can be found in req.params().
 *   console.log('params: ' + req.params());
 *   // Whatever is placed in res.reply() will be the return value from ILX::call.
 *   res.reply('<RESPONSE>');
 * });
 */


/* Start listening for ILX::call and ILX::notify events. */
ilx.listen();




