const config = require('../config');
var WSFEDStrategy = require('passport-wsfed-saml2').Strategy;
const Utils = require('../utils/HelperUtils');
var PGEntitySSOConfiguration = require('../repositories/PGEntitySSOConfiguration');
var PGEntitySSOConfiguration = new PGEntitySSOConfiguration();

function WSFEDConfiguration() {

};

WSFEDConfiguration.prototype.getConfig = function(appCredentials, callback) {
   var params = [appCredentials.client_id, Utils.encryptClientKey(appCredentials.client_key)];
    try {
        PGEntitySSOConfiguration.getSSOConfiguration(params, function(err, res) { 
            if (!err) {
                if (typeof(res.wsfed) == 'undefined') {
                    var err = new Error("Invalid client Id or Secret Key");
                    err.status = 401;
                    return callback(err, null);
                } 
                var stratgey =  new WSFEDStrategy({
                                    realm: res.wsfed.realm,
                                    homeRealm: res.wsfed.homeRealm,
                                    identityProviderUrl: res.wsfed.idpUrl,
                                    thumbprint: res.wsfed.thumbprint       
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



