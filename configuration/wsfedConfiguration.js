const config = require('../config');
var WSFEDStrategy = require('passport-wsfed-saml2').Strategy;
const Utils = require('../utils/HelperUtils');
var PGEntitySSOConfig = require('../repositories/PGEntitySSOConfig');
var PGEntitySSOConfig = new PGEntitySSOConfig();

function WSFEDConfiguration() {

};

WSFEDConfiguration.prototype.getConfig = function(appCredentials, callback) {
   var params = [appCredentials.client_id, Utils.encryptClientKey(appCredentials.client_key), 'wsfed'];
    try {
        PGEntitySSOConfig.getSSOConfig(params, function(err, res) { 
            if (!err) {
                if (typeof(res.config) == 'undefined') {
                    var err = new Error("Invalid client Id or Secret Key");
                    err.status = 401;
                    return callback(err, null);
                } 
                var stratgey =  new WSFEDStrategy({
                                    realm: res.config.realm,
                                    homeRealm: res.config.homeRealm,
                                    identityProviderUrl: res.config.idpUrl,
                                    thumbprint: res.config.thumbprint       
                                },
                                function(profile, done) {
                                    process.nextTick(function() {
                                        return done(null, profile);
                                    })
                                });
                callback(err, stratgey);
            } else { 
                callback(err, null);
            }
        });
    } catch(error) {
        callback(error, null);
    }
};


module.exports = WSFEDConfiguration;



