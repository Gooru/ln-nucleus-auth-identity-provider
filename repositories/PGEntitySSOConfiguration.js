var DBTransaction = require('./DBTransaction');
var DBTransaction = new DBTransaction();

function PGEntitySSOConfiguration() {
    
};

const SELECT_SSO_CONFIGURATION = "select wsfed from sso_configuration where id = $1::uuid AND secret = $2::varchar";

PGEntitySSOConfiguration.prototype.getSSOConfiguration = function(params, callback) {
    DBTransaction.executeQuery(SELECT_SSO_CONFIGURATION, params , function(err, res) {
        if (err) { 
            callback(err, {});
        } else {
            var result = typeof(res.rows[0]) != 'undefined' ? res.rows[0] : {};
           callback(err, result);
        }
    });
};

module.exports = PGEntitySSOConfiguration;
