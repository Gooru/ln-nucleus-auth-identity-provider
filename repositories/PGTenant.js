var DBTransaction = require('./DBTransaction');
var DBTransaction = new DBTransaction();

function PGTenant() {
    
};

const SELECT_TENANT = "select wsfed_config from tenant where id = $1::uuid AND secret = $2::varchar";

PGTenant.prototype.getTenant = function(params, callback) {
    DBTransaction.executeQuery(SELECT_TENANT, params , function(err, res) {
        if (err) { 
            callback(err, {});
        } else {
            var result = typeof(res.rows[0]) != 'undefined' ? res.rows[0] : {};
           callback(err, result);
        }
    });
};

module.exports = PGTenant;