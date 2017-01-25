var express = require('express');
var router = express.Router();
var Passport = require('passport').Passport;
var SamlStrategy = require('passport-saml');
var config = require('../config');
var logger = require('../log');
var authenticate = require('./authenticate');
var fs = require('fs');

var passport = new Passport();

passport.serializeUser(function(user, done) {
    done(null, user);
});
passport.deserializeUser(function(user, done) {
    done(null, user);
});

var shibStrategy = new SamlStrategy.Strategy({
        callbackUrl: config.shibboleth.callbackUrl,
        entryPoint: config.shibboleth.entryPoint,
        issuer: config.shibboleth.issuer,
		forceAuthn: config.shibboleth.forceAuthn,
		identifierFormat: config.shibboleth.identifierFormat,
		decryptionPvk: fs.readFileSync('./cert/privateKey.pem', 'utf8')
    },
    function(profile, done) {
		process.nextTick(function () {
			return done(null, profile);
		});
	}
);

passport.use(shibStrategy);

router.use(function(req, res, next) {
    var entryPoint = req.query.entryPoint;
	if (typeof entryPoint !== "undefined") {
		shibStrategy._saml.options.entryPoint = entryPoint;
	}
    next();
});

router.get('/', 
	passport.authenticate('saml', {
	    failureRedirect: '/',
	    failureFlash: true,
		requestMethod: 'post'
	})
);

router.post('/callback',
	passport.authenticate('saml', {
        failureRedirect: '/',
        failureFlash: true
    }),
    function(req, res) {
		var profile = req.user;
		var options = {};
        options.user = {};
		options.user.firstname = (profile.firstName != null ? profile.firstName : "firstname");
        options.user.lastname = (profile.lastName != null ? profile.lastName : "lastname");
        options.user.identity_id = profile.eppn;
        options.grant_type = "saml";
		
        new authenticate(req, res, options);

    }
);

router.get('/generateMetadata', function(req, res) {
  res.type('application/xml');
  res.status(200).send(shibStrategy.generateServiceProviderMetadata(fs.readFileSync('./cert/decryptionCert.pem', 'utf8')));

});

module.exports = router;
