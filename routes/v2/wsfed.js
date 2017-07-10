var express = require('express');
var router = express.Router();
var passport = require('passport');
var config = require('../../config');
var logger = require('../../log');
var queryString = require('qs');
var superagent = require('superagent');
var WSFEDConfiguration = require('../../configuration/wsfedConfiguration');
var WSFEDConfiguration = new WSFEDConfiguration();
const configKeyPrefix = "WSFED-";


router.get('/login', function(req, res, next) {
    logger.info("Version 2 : Wsfed  signin entry point ...");
    const appCredentials = getAppCredentials(req);
    var callbackUrl = req.query.redirectURI;
    if (typeof(callbackUrl) == 'undefined' || callbackUrl.length == 0) {
      callbackUrl  = req.protocol  + '://' + config.domainName;
    }
    WSFEDConfiguration.getConfig(appCredentials, function(err, wsfedConfig) {
        if (!err) {
            passport.use(getConfigStorageKey(appCredentials.client_id) , wsfedConfig);
            passport.authenticate(getConfigStorageKey(appCredentials.client_id), {
                failureRedirect: '/',
                failureFlash: true ,
                wreply: callbackUrl + '~~' + appCredentials.client_id + '~~' + appCredentials.client_key
            })(req, res, next);
        } else {
            next(err);
        }
    });
});

router.post("/login", (req, res, next) => {
  const url = queryString.parse(req.headers.referer);
  const wreply = url['wreply'];
  const data =  wreply.split('~~');
  const options = {};
  const redirectUrl = data[0];
  options.client_id = data[1];
  options.client_key = data[2];
  passport.authenticate(getConfigStorageKey(options.client_id), (err, profile, info) => {
        var username = profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name'];
        options.user = {};
        options.user.first_name = profile['http://identityserver.thinktecture.com/claims/profileclaims/firstname'];
        options.user.last_name =  profile['http://identityserver.thinktecture.com/claims/profileclaims/lastname'];
        var role = profile['http://schemas.microsoft.com/ws/2008/06/identity/claims/role'];
        options.grant_type = "wsfed";
	options.user.username = username.replace(/[^a-z\d\s]+/gi, "");
	options.user.username = options.user.username.substring(0,18);
        if(profile.email != null) {
            options.user.identity_id = profile.email;
        }
        else {
            options.user.identity_id = options.user.username;
        }
        authenticate(req, res, redirectUrl, options);
  })(req, res, next)
});


function authenticate(req, res, redirectUrl, options) {
    superagent.post(config.hostname + '/api/nucleus-auth/v1/authorize').send(options).set('user-agent',req.headers['user-agent'])
        .end(function(e, response) {
           var xForward = typeof(req.headers['x-forwarded-proto']) !== "undefined" ? req.headers['x-forwarded-proto'] : req.protocol;
            var domainName =  xForward  + '://' + config.domainName;
            if (!e && (response.status == 200 || response.status == 201)) {
                var json = JSON.parse(response.text);
                res.statusCode = 302;
                var callBackMethod = 'POST';
                if (typeof(redirectUrl) === "undefined" || redirectUrl.length <= 0) {
                    redirectUrl = domainName;
                } 
                redirectUrl += "?access_token=" + json.access_token;
                res.setHeader('Location', redirectUrl);
            } else {
                logger.error("WSFED Authentication failure :");
                logger.error(response.text);
                res.statusCode = 302;
                res.setHeader('Location', domainName);
            }
            res.end();
     });

}

function getAppCredentials(request) { 
   var reqparams = {};
   if (typeof(request.query.client_key) != 'undefined' && typeof(request.query.client_id) != 'undefined') { 
       reqparams.client_id = request.query.client_id;
       reqparams.client_key = request.query.client_key;
   } else { 
        // setting default value of Gooru Client key and Id, If client id and key does not exist in request parameter
        reqparams.client_key = config.client_key;
        reqparams.client_id =  config.client_id;
   }
   return reqparams;
}

function getConfigStorageKey(id) { 
    return configKeyPrefix + id;
}

module.exports = router;
