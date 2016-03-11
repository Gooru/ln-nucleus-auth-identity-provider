var express = require('express');
var router = express.Router();
var passport = require('passport')
var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
var config = require('../config');
var logger = require('../log');
var authenticate = require('./authenticate');

passport.serializeUser(function(user, done) {
    done(null, user);
});
passport.deserializeUser(function(obj, done) {
    done(null, obj);
});

passport.use(new GoogleStrategy({
        clientID: config.gmail.clientID,
        clientSecret: config.gmail.clientSecret,
        callbackURL: config.baseUrl + '/api/nucleus-auth-idp/v1/google/callback'
    },

    function(request, accessToken, refreshToken, profile, done) {
        process.nextTick(function() {
            return done(null, profile);
        })
    }));
router.get("/", function(request, response) {
   logger.info("Google signin entry point ...");
   var callbackUrl = typeof(request.query.callBackUrl) ? request.query.callBackUrl : request.query.redirectURL;
   if (typeof(callbackUrl) == 'undefined' || callbackUrl.length == 0) {
      callbackUrl  = request.protocol  + ':' + config.gmail.redirectUrl;
   }

    passport.authenticate('google', {
        scope: [
            config.gmail.scopeProfile,
            config.gmail.scopeEmail
        ],
        state: callbackUrl
    })(request, response)
});

router.get('/callback',
    passport.authenticate('google', {
        failureRedirect: '/'
    }),

    function(req, res) {
        var profile = req.user;
        var options = {};
        options.user = {};
        options.user.firstname = profile._json.given_name;
        options.user.lastname = profile._json.family_name;
        options.user.identity_id = profile._json.email;
        options.grant_type = "google";
         logger.info("Callback from google ..." + profile._json.email);
        new authenticate(req, res, options);

    });




module.exports = router;
