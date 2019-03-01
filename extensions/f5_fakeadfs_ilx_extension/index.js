// Import the f5-nodejs module.
var f5 = require('f5-nodejs');

//server.js
// Fake ADFS
// WS-Federation IDP
// Michael Coleman
//
// Some things are hardcoded for testing purposes while i develop and test.

var path = require('path');
var jsonQuery = require('json-query');
var config = require('read-config')(path.join(__dirname, 'config.json'));
var queryString = require('querystring');
var fs = require('fs');
var moment = require('moment');
var url = require('url');

var timeout = config.federation.timeout;

// Federation Values
var wsfedIssuer = config.federation.issuer;

var SigningCert = fs.readFileSync(path.join(__dirname, config.federation.certs.tokensigningcert));
var SigningKey = fs.readFileSync(path.join(__dirname, config.federation.certs.tokensigningkey));

var wsfed = require('ws-star').WSFed;

/* These are for IDP initated SSO requets, since the Querystring will be
   blank.
   */

var idp_WA = 'signin1.0'
var idp_WTRealm = 'urn:sharepoint:f5lab'
var idp_WCTX = ''

// Create a new rpc server for listening to TCL iRule calls.
var ilx = new f5.ILXServer();

ilx.addMethod('Generate-WSTrustToken', function(req, res) {
  try{
  var query = queryString.unescape(req.params()[0])
  var queryOptions = queryString.parse(query)
  var AttrUserName = req.params()[1]
  var AttrUserPrincipal = req.params()[2]
  var AttrDisplayname = AttrUserName
  var AttrUserRole = 'ClaimsUser'
  var AttrUserSID = req.params()[4]

  var relyingpartners = config.federation
  var EndPointfilter = jsonQuery('relyingpartners[name=' + wtrealm + '].options.endpoints.url', { data: relyingpartners})
  var endPoint = EndPointfilter.value

  }
})

ilx.addMethod('Generate-WSFedToken', function(req, res) {
try {
    /* Extract the ILX parameters to add to the Assertion data
       req.params()[0] is the first passed argument
       req.params()[1] is the second passed argument, and so on.

    Exchange uses/requires sid and upn

    "attributes": {
      "email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
      "sid" : "http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid",
      "upn": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn",
      "givenname": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
      "displayname": "http://schemas.microsoft.com/ws/2008/06/identity/claims/userdata",
      "surname": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
      "group": "http://schemas.xmlsoap.org/claims/Group",
      "role": "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
      "windowsaccount": "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname"
    }
    */

  var query = queryString.unescape(req.params()[0])
  var queryOptions = queryString.parse(query)
  var AttrUserName = req.params()[1]
  var AttrUserPrincipal = req.params()[2]
  var AttrDisplayname = AttrUserName
  var AttrUserRole = 'ClaimsUser'
  var AttrUserSID = req.params()[4]

      /* If incoming request is IDP initiated, the Querystrings will not
       be populated, so lets check, and if undefined, populate with static
       IDP config vars.
       */
  var wa = queryOptions.wa
  if (typeof wa === 'undefined') {
    wa = idp_WA
  }
  var wtrealm = queryOptions.wtrealm
  if (typeof wtrealm === 'undefined') {
    wtrealm = idp_WTRealm
  }
  var wctx = queryOptions.wctx
  if (typeof wctx === 'undefined') {
    wctx = idp_WCTX
  }

  var relyingpartners = config.federation
  var EndPointfilter = jsonQuery('relyingpartners[name=' + wtrealm + '].options.endpoints.url', { data: relyingpartners})
  var endPoint = EndPointfilter.value

    /* Generate WSFed Assertion.  These attributes are
       configured previously in the code.
       cert: this is the cert used for encryption
       key: this is the key used for the cert
       issuer: the assertion issuer
       lifetimeInSeconds: timeout
       audiences: this is the application ID for sharepoint, urn:sharepoint:webapp
       attributes:  these should map to the mappings created for the IDP in SharePoint
       */

  var wsfed_options = {
    wsaAddress: wtrealm,
    cert: SigningCert,
    key: SigningKey,
    issuer: wsfedIssuer,
    lifetimeInSeconds: timeout,
    audiences: wtrealm,
    attributes: {
      'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': AttrUserName,
      'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn': AttrUserPrincipal,
      'http://schemas.microsoft.com/ws/2008/06/identity/claims/role': AttrUserRole,
      'http://schemas.microsoft.com/ws/2008/06/identity/claims/userdata': AttrDisplayname,
      'http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid': AttrUserSID
    }
  }
      /* Sign the Assertion */
  var signedAssertion = wsfed.create(wsfed_options)

  } catch (e) {
    res.reply("error: " + e.message + ", stack: " + e.stack);
    return;
  }
  res.reply(signedAssertion);
})

// Start listening for ILX::call and ILX::notify events.
ilx.listen()





