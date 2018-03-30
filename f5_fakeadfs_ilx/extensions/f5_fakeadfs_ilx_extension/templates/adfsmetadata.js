var utils = require('./utils.js')
var Parser = require('xmldom').DOMParser
//var encoders = require('./encoders')
var xmlenc = require('xml-encryption')
var SignedXml = require('xml-crypto').SignedXml
var fs = require('fs')
var path = require('path')

// console.log('START');

// Load FederationMetadata Template
var federationMetadata = fs.readFileSync(path.join(__dirname, '/adfsmetadata.template')).toString()

var NAMESPACE = 'urn:oasis:names:tc:SAML:2.0:metadata'

var algorithms = {
  signature: {
    'rsa-sha256': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    'rsa-sha1': 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
  },
  digest: {
    'sha256': 'http://www.w3.org/2001/04/xmlenc#sha256',
    'sha1': 'http://www.w3.org/2000/09/xmldsig#sha1'
  }
}

function getEndpointAddress (req, endpointPath) {
  endpointPath = endpointPath || (req.originalUrl.substr(0, req.originalUrl.length - URL_PATH.length))
  return utils.getBaseUrl(req) + endpointPath
}

function sign (options, sig, doc, callback) {
  var token = utils.removeWhitespace(doc.toString())
  var signed

  try {
    var opts = options.xpathToNodeBeforeSignature ? {
      location: {
        reference: options.xpathToNodeBeforeSignature,
        action: 'after'
      }
    } : {}

    sig.computeSignature(token, opts)
    signed = sig.getSignedXml()
  } catch (err) {
    return utils.reportError(err, callback)
  }

  if (!callback) return signed

  return callback(null, signed)
}

function generatemetadata (options, reqissuer, reqendpoint) {
  options = options || {}

  if (!options.issuer) {
    throw new Error('options.issuer is required')
  }

  if (!options.cert) {
    throw new Error('options.cert is required')
  }
  if (!options.key) {
    throw new Error('options.key is required')
  }

  options.signatureAlgorithm = options.signatureAlgorithm || 'rsa-sha256'
  options.digestAlgorithm = options.digestAlgorithm || 'sha256'

  var cert = utils.pemToCert(options.cert)

  var sig = new SignedXml(null, { signatureAlgorith: algorithms.signature[options.signatureAlgorithm], idAttribute: 'ID' })
  sig.addReference("//*[local-name(.)='EntityDescriptor']", ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', 'http://www.w3.org/2001/10/xml-exc-c14n#'], algorithms.digest[options.digestAlgorithm])

  sig.signingKey = options.key

  sig.keyInfoProvider = {
    getKeyInfo: function () {
      return '<X509Data><X509Certificate>' + cert + '</X509Certificate></X509Data>'
    }
  }

  var issuer = options.issuer
  var pem = encoders.removeHeaders(options.cert)
  var endpoint = reqissuer + reqendpoint
  var mexEndpoint = reqissuer + reqendpoint

  var doc
  try {
    doc = new Parser().parseFromString(federationMetadata.toString())
  } catch (err) {
    return utils.reportError(err, callback)
  }

  // Set ID and Issuer in Metadata
  doc.documentElement.setAttribute('ID', '_' + (options.uid || utils.uid(32)))
  doc.documentElement.setAttribute('entityID', (options.issuer || 'https://test.domain.com/STS'))

  // Insert Signing Key
  var roleDescriptor = doc.getElementsByTagName('RoleDescriptor')[0]
  var keyDescriptor = doc.createElement('KeyDescriptor')
  keyDescriptor.setAttribute('use', 'signing')
  roleDescriptor.appendChild(keyDescriptor)
  var keyInfo = doc.createElement('KeyInfo')
  keyInfo.setAttribute('xmlns', 'http://www.w3.org/2000/09/xmldsig#')
  keyDescriptor.appendChild(keyInfo)
  var x509data = doc.createElement('X509Data')
  keyInfo.appendChild(x509data)
  var x509Cert = doc.createElement('X509Certificate')

  var pemText = doc.createTextNode(cert)
  x509Cert.appendChild(pemText)
  x509data.appendChild(x509Cert)

  if (!options.encryptionCert) return sign(options, sig, doc)
}

function encrypt (options, signed, callback) {
  var encryptOptions = {
    rsa_pub: options.encryptionPublicKey,
    pem: options.encryptionCert,
    encryptionAlgorithm: options.encryptionAlgorithm || 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
    keyEncryptionAlgorighm: options.keyEncryptionAlgorighm || 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'
  }

  xmlenc.encrypt(signed, encryptOptions, function (err, encrypted) {
    if (err) return callback(err)
    callback(null, utils.removeWhitespace(encrypted))
  })
}

module.exports = generatemetadata

// function test () {
//  var SigningCertpath = '/fakeadfs.f5lab.com.crt'
//  var SigningKeypath = '/fakeadfs.f5lab.com.key'
//
//  var SigningCert = fs.readFileSync(__dirname + SigningCertpath)
//  var SigningKey = fs.readFileSync(__dirname + SigningKeypath)
//
//  var opts = {
//  //    issuer: 'https://fakeadfs.f5lab.com',
//  //    endpointPath: '/federationmetadata/2007-06/federationmetadata.xml',
//  //    cert: SigningCert,
//  //    key: SigningKey
//  }
//  var console = generatemetadata(opts, 'https://fakeadfs.f5lab.com', '/federationmetadata/2007-06/federationmetadata.xml')
//  return console
// }

// console.log(test());
