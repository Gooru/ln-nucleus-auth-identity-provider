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
    const client_id = req.query.client_id;
    if (typeof(client_id) == 'undefined') { 
         var err = new Error("Client id missing.");
         err.status = 401;
         return next(err);
    }
    WSFEDConfiguration.getConfig(client_id, function(err, strategy, wsfedConfig) {
        if (!err) {
            passport.use(getConfigStorageKey(client_id), strategy);
            passport.authenticate(getConfigStorageKey(client_id), {
                failureRedirect: '/',
                failureFlash: true,
                wctx: wsfedConfig.redirectURI
            })(req, res, next);
        } else {
           return next(err);
        }
    });
});

router.post("/login", (req, res, next) => {
  const wctx = req.body.wctx;
  const requestBody = {};
  const redirectUrl = wctx;
  const appCredentials = getAppCredentials(req);
  const clientId = appCredentials.client_id;
  const clientKey = appCredentials.client_key;
  const basicAuthToken = new Buffer((clientId + ":" + clientKey)).toString('base64');
  passport.authenticate(getConfigStorageKey(clientId), (err, profile, info) => {
        var username = profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name'];
        requestBody.user = {};
        requestBody.user.first_name = profile['http://identityserver.thinktecture.com/claims/profileclaims/firstname'];
        requestBody.user.last_name =  profile['http://identityserver.thinktecture.com/claims/profileclaims/lastname'];
        var role = profile['http://schemas.microsoft.com/ws/2008/06/identity/claims/role'];
        requestBody.grant_type = "wsfed";
	if(username != null) {
            requestBody.user.reference_id = requestBody.user.username;
        }
        else if (profile.email != null) {
            requestBody.user.reference_id = profile.email;
        }
        if (profile.email != null) { 
            requestBody.user.email = profile.email;
        }
        authenticate(req, res, redirectUrl, requestBody, basicAuthToken);
  })(req, res, next)
});


function authenticate(req, res, redirectUrl, requestBody, basicAuthToken) {
    superagent.post(config.authHandlerInternalHostName + '/api/internal/v2/sso/wsfed').send(requestBody).set('user-agent',req.headers['user-agent']).set('authorization', 'Basic ' + basicAuthToken).end(function(e, response) {
           var xForward = typeof(req.headers['x-forwarded-proto']) !== "undefined" ? req.headers['x-forwarded-proto'] : req.protocol;
            var domainName =  xForward  + '://' + config.domainName;
            if (!e && (response.status == 200 || response.status == 201)) {
                var json = JSON.parse(response.text);
                res.statusCode = 302;
                if (typeof(redirectUrl) === "undefined" || redirectUrl.length <= 0) {
                    redirectUrl = domainName;
                } 
                redirectUrl += "?access_token=" + json.access_token;
                res.setHeader('Location', redirectUrl);
            } else {
                logger.error("V2 WSFED Authentication failure :");
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
