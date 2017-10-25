var DBTransaction = require('./DBTransaction');
var DBTransaction = new DBTransaction();

function PGEntitySSOConfig() {
    
};

const SELECT_SSO_CONFIG = "select config from sso_config where domain = $1::varchar AND sso_type= $2::varchar";
const SELECT_SECRET = "select secret from sso_config where id = $1::uuid";

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

PGEntitySSOConfig.prototype.getSecret = function(params, callback) {
	DBTransaction.executeQuery(SELECT_SECRET, params , function(err, res) {
        if (err) {
            callback(err, {});
        } else {
            var result = typeof(res.rows[0]) != 'undefined' ? res.rows[0] : {};
           callback(err, result);
        }
    });
};

module.exports = PGEntitySSOConfig;
