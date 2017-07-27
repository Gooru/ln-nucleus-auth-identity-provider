const config = require('../config');
var WSFEDStrategy = require('passport-wsfed-saml2').Strategy;
var PGEntitySSOConfig = require('../repositories/PGEntitySSOConfig');
var PGEntitySSOConfig = new PGEntitySSOConfig();

function WSFEDConfiguration() {

};

WSFEDConfiguration.prototype.getConfig = function(client_id, callback) {
   var params = [client_id, 'wsfed'];
    try {
        PGEntitySSOConfig.getSSOConfig(params, function(err, res) { 
            if (!err) {
                if (typeof(res.config) == 'undefined') {
                    var err = new Error("Invalid client Id");
                    err.status = 401;
                    return callback(err, null);
                }
                var strategy =  new WSFEDStrategy({
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
                return callback(err, strategy, res.config);
            } else { 
               return  callback(err, null, null);
            }
        });
    } catch(error) {
        return callback(error, null, null);
    }
};


module.exports = WSFEDConfiguration;



