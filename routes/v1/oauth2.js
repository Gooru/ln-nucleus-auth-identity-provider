var express = require('express');
var router = express.Router();
var passport = require('passport');
var config = require('../../config');
var LOGGER = require('../../log');
var queryString = require('qs');
var superagent = require('superagent');
var flatten = require('flat');
var OAUTH2Config = require('./oauth2Configuration');
var OAUTH2Configuration = new OAUTH2Config();
const configKeyPrefix = "OAUTH2-";
const MANDATORY_CONFIG_KEYS = ["authorization_url", "client_id", "token_url", "client_secret", "scope", "callback_url", "response_type", "profile.api_url", "profile.auth_header_placeholder", "profile.response_mapper.first_name"];

router.get('/:shortname', function(req, res, next) {
  LOGGER.debug("V1: GET entry");
  const shortname = req.params.shortname;
  LOGGER.info("v1 : OAuth login entry point for partner :=" + shortname);

  if (shortname) {
    OAUTH2Configuration.getConfig(shortname, function(err, strategy, OAUTH2Config) {
      if (!err) {
        if (validateOAuth2ConfigSettings(OAUTH2Config)) {
          passport.use(getConfigStorageKey(shortname), strategy);
          passport.authenticate(getConfigStorageKey(shortname), {
            failureRedirect: '/',
            failureFlash: true
          })(req, res, next);
        } else {
          let err = new Error("Internal server error");
          err.status = 500;
          return next(err);
          LOGGER.info("Oauth2 config setting is not updated correctly, check  the mandatory key values.");
        }
      } else {
        return next(err);
      }
    });
  } else {
    let err = new Error("Unauthorized Access");
    err.status = 401;
    return next(err);
  }
});

router.get("/:shortname/callback", (req, res, next) => {
  LOGGER.debug("v1: Processing GET Login request callback");
  const shortname = req.params.shortname;
  LOGGER.info("v1 : OAuth login callback entry point for partner :=" + shortname);

  OAUTH2Configuration.getConfig(shortname, function(err, strategy, oauth2Config, clientId, secret) {

    passport.use(getConfigStorageKey(shortname), strategy);

    passport.authenticate(getConfigStorageKey(shortname), (err, accessToken, profile) => {
      let profileUrl = oauth2Config.profile.api_url;
      let authHeaderPlaceholder = oauth2Config.profile.auth_header_placeholder;
      let profileResponseMapper = oauth2Config.profile.response_mapper;
      let redirectUrl = oauth2Config.home_page_url;

      profileInfo(req, res, profileUrl, authHeaderPlaceholder, accessToken, function(err, response) {
        if (!err) {
          let responseBody = flatten(response.body);
          let profile = profileInfoMapper(profileResponseMapper, responseBody);
          let requestBody = {
            "grant_type": "oauth2",
            "user": profile
          };
          const basicAuthToken = new Buffer((clientId + ":" + secret)).toString('base64');
          authenticate(req, res, redirectUrl, requestBody, basicAuthToken);
        } else {
          let err = new Error("Unauthorized Access");
          err.status = 401;
          return next(err);
        }
      });
    })(req, res, next)
  });
});


function authenticate(req, res, redirectUrl, requestBody, basicAuthToken) {
  LOGGER.debug("redirect URL:" + redirectUrl);
  superagent.post(config.authHandlerInternalHostName + '/api/internal/v2/sso/oauth2')
    .send(JSON.stringify(requestBody))
    .set('user-agent', req.headers['user-agent'])
    .set('authorization', 'Basic ' + basicAuthToken)
    .end(function(e, response) {
      let xForward = typeof(req.headers['x-forwarded-proto']) !== "undefined" ? req.headers['x-forwarded-proto'] : req.protocol;
      let domainName = xForward + '://' + config.domainName;
      if (!e && (response.status == 200 || response.status == 201)) {
        let json = JSON.parse(response.text);

        if (redirectUrl == null || redirectUrl.length <= 0) {
          redirectUrl = domainName;
        }

        if (redirectUrl.indexOf("?") >= 0) {
          redirectUrl += "&access_token=" + json.access_token;
        } else {
          redirectUrl += "?access_token=" + json.access_token;
        }

        res.statusCode = 302;
        res.setHeader('Location', redirectUrl);
      } else {
        LOGGER.error("V1 Oauth2 Authentication failure :");
        if (response) {
          LOGGER.error(response.text);
        }
        res.statusCode = 302;
        res.setHeader('Location', domainName);
      }
      res.end();
    });
}

function getConfigStorageKey(id) {
  return configKeyPrefix + id;
};


function profileInfo(req, res, profileUrl, authHeaderPlaceholder, accessToken, next) {
  let authorizationHeader = authHeaderPlaceholder.replace('[tokenValue]', accessToken);
  LOGGER.debug("profile info:" + profileUrl);
  superagent.get(profileUrl)
    .set('user-agent', req.headers['user-agent'])
    .set('Authorization', authorizationHeader)
    .end(function(e, response) {
      if (!e) {
        return next(null, response);
      } else {
        return next(e, null);
      }
    });
}

function profileInfoMapper(profileResponseMapper, profileInfo) {
  let profile = {};
  for (let key in profileResponseMapper) {
    if (profileResponseMapper.hasOwnProperty(key)) {
      let value = profileResponseMapper[key];
      let profileData = profileInfo[value];
      if (profileData) {
        profile[key] = profileData.toString();
      }
    }
  }
  return profile;
}

function validateOAuth2ConfigSettings(OAUTH2Config) {
  let oauth2Config = flatten(OAUTH2Config);
  let oauth2ConfigKeys = Object.keys(oauth2Config);
  for (let index = 0; index < MANDATORY_CONFIG_KEYS.length; index++) {
    let value = MANDATORY_CONFIG_KEYS[index];
    if (!oauth2ConfigKeys.includes(value)) {
      return false;
    }
  }
  return true;
}

module.exports = router;
