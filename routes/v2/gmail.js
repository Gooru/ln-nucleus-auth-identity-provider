var express = require('express');
var router = express.Router();
var passport = require('passport')
var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
var superagent = require('superagent');
var config = require('../../config');
var logger = require('../../log');
var GmailConfig = require('../../configuration/gmailConfiguration');
var GmailConfiguration = new GmailConfig();

passport.serializeUser(function(user, done) {
	done(null, user);
});

passport.deserializeUser(function(obj, done) {
	done(null, obj);
});

var gmailGetRouteHandler = function(request, response, next) {
	logger.info("v2 Google signin entry point ...");

	var tenantId = request.query.tenantId;
	logger.info("tenantId found in request:" + tenantId);

	// If there is no tenant id in the request then fallback on default from
	// config
	if (typeof (tenantId) == 'undefined') {
		tenantId = config.client_id;
	}

	logger.info("getting gmail config from database for tenant:" + tenantId);
	GmailConfiguration.getConfig(tenantId, function(err, gmailConfig) {
		if (!err) {
			logger.debug("got config from database");
			passport.use(new GoogleStrategy({
				clientID : gmailConfig.config.clientId,
				clientSecret : gmailConfig.config.clientSecret,
				callbackURL : gmailConfig.config.callBackUrl
			}, function(request, accessToken, refreshToken, profile, done) {
				process.nextTick(function() {
					return done(null, profile);
				})
			}));

			stateJson = {
				tenantId : tenantId,
				redirectUrl : gmailConfig.config.redirectUrl
			};

			passport.authenticate('google', {
				scope : [ config.gmail.scopeProfile, config.gmail.scopeEmail ],
				state : JSON.stringify(stateJson)
			})(request, response)
		} else {
			logger.error("unable to get config of the tenant: " + tenantId);
			return next(err);
		}
	});
};

router.get("/", gmailGetRouteHandler);

router.get('/callback', passport.authenticate('google', {
	failureRedirect : '/'
}),

function(req, res) {
	var profile = req.user;
	var options = {};
	options.user = {};
	options.user.first_name = profile._json.given_name;
	options.user.last_name = profile._json.family_name;
	options.user.identity_id = profile._json.email;
	options.grant_type = "google";
	logger.info("Callback from v2 google ..." + profile._json.email);

	var stateJson = JSON.parse(req.query.state);
	options.callBackUrl = stateJson.redirectUrl;
	logger.info("Checking tenant:" + stateJson.tenantId);

	if (stateJson.tenantId) {
		options.client_id = stateJson.tenantId;
		GmailConfiguration.getConfig(options.client_id, function(err,
				gmailConfig) {
			if (!err) {
				logger.info("got config from database");
				options.client_key = gmailConfig.secret;
				var requiredDomains = gmailConfig.config.domains;
				logger.info("veryfying email domains:" + requiredDomains);
				if (requiredDomains !== null) {
					logger.info("not null domains");
					if (isVerifiedDomain(options.user.identity_id,
							requiredDomains)) {
						logger.info("email domain verified successfully");
						authenticate(req, res, options);
					} else {
						logger.info("Unauthorized domain");
						res.statusCode = 403;
						res.message = "access from unauthorized domain";
						res.end();
					}
				} else {
					logger.info("null domains");
					authenticate(req, res, options);
				}

			} else {
				logger.error("unable to get config of the tenant: "
						+ options.client_id);
				res.statusCode = 401;
				res.message = "access from unauthorized tenant";
				res.end();
			}
		});
	} else {
		logger.debug("no tenant default authenticate");
		options.client_id = config.client_id;
		options.client_key = config.client_key;
		authenticate(req, res, options);
	}
});

function isVerifiedDomain(email, requiredDomains) {
	var emailDomain = email.split('@')[1];
	var requiredDomainsArray = JSON.stringify(requiredDomains);
	return requiredDomainsArray.includes(emailDomain);
}

function authenticate(req, res, options) {

	var callBackUrl = options.callBackUrl;
    delete options.callBackUrl;
    
	superagent
			.post(config.hostname + '/api/nucleus-auth/v1/authorize')
			.send(options)
			.set('user-agent', req.headers['user-agent'])
			.end(
					function(e, response) {
						var xForward = typeof (req.headers['x-forwarded-proto']) !== "undefined" ? req.headers['x-forwarded-proto']
								: req.protocol;
						var domainName = xForward + '://' + config.domainName;
						if (!e
								&& (response.status == 200 || response.status == 201)) {
							var json = JSON.parse(response.text);
							res.statusCode = 302;
							var redirectUrl = null;

							if (typeof (callBackUrl) !== 'undefined') {
								redirectUrl = callBackUrl
							} else {
								redirectUrl = domainName;
							}		

							if (redirectUrl.indexOf("?") >= 0) {
								redirectUrl += "&access_token="
										+ json.access_token;
							} else {
								redirectUrl += "?access_token="
										+ json.access_token;
							}

							res.setHeader('Location', redirectUrl);
						} else {
							logger.error(" Authentication failure :");
							logger.error(response.text);
							res.statusCode = 302;
							res.setHeader('Location', domainName);
						}
						res.end();
					});

}

module.exports = router;