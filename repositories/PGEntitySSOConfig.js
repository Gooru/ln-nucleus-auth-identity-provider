var DBTransaction = require('./DBTransaction');
var DBTransaction = new DBTransaction();

function PGEntitySSOConfig() {
    
};

const SELECT_SSO_CONFIG = "select config from sso_config where id = $1::uuid AND secret = $2::varchar AND sso_type= $3::varchar";

PGEntitySSOConfig.prototype.getSSOConfig = function(params, callback) {
    DBTransaction.executeQuery(SELECT_SSO_CONFIG, params , function(err, res) {
        if (err) {
            callback(err, {});
        } else {
            var result = typeof(res.rows[0]) != 'undefined' ? res.rows[0] : {};
           callback(err, result);
        }
    });
};

module.exports = PGEntitySSOConfig;
