const config = require('../config');
var WSFEDStrategy = require('passport-wsfed-saml2').Strategy;
const Utils = require('../utils/HelperUtils');
var PGEntityTenant = require('../repositories/PGEntityTenant');
var PGEntityTenant = new PGEntityTenant();

function WSFEDConfiguration() {

};

WSFEDConfiguration.prototype.getConfig = function(appCredentials, callback) {
   var params = [appCredentials.client_id, Utils.encryptClientKey(appCredentials.client_key)];
    try {
        PGEntityTenant.getTenant(params, function(err, res) { 
            if (!err) {
                if (typeof(res.wsfed_config) == 'undefined') {
                    var err = new Error("Invalid client Id or Secret Key");
                    err.status = 400;
                    return callback(err, null);
                } 
                var stratgey =  new WSFEDStrategy({
                                    realm: res.wsfed_config.realm,
                                    homeRealm: res.wsfed_config.homeRealm,
                                    identityProviderUrl: res.wsfed_config.idpUrl,
                                    thumbprint: res.wsfed_config.thumbprint       
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



