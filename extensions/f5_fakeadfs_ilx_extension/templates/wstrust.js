
var utils = require('./utils'),
    Parser = require('xmldom').DOMParser,
    SignedXml = require('xml-crypto').SignedXml,
    xmlenc = require('xml-encryption'),
    moment = require('moment');
    async = require('async');
    crypto = require('crypto');
    url = require('url');

var fs = require('fs');
var path = require('path');

var momenttz = require('moment-timezone');

var rst = fs.readFileSync(path.join(__dirname, 'wstrust.template')).toString();

// Current iteration will only support usernameMixed, can look at adding Certificate and other options later
//
exports.create = function(options, callback) {
  if (!options.endpoint)
    throw new Error('Expect an Endpoint');
  if (!options.username)
    throw new Error('Expect a username');
  if (!options.password)
    throw new Error('Expect a password');
  if (!options.audience)
    throw new Error('Expect an audience');
}

var message = rst;

var uri = url.parse(options.endpoint);

message = message.replace("[To]", options.endpoint);
message = message.replace("[Username]", options.username);
message = message.replace("[Password]", options.password);
message = message.replace("[ApplyTo]", options.scope);

return message;
