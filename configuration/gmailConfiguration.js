var PGEntitySSOConfig = require('../repositories/PGEntitySSOConfig');
var ssoConfig = new PGEntitySSOConfig();

function GmailConfiguration() {
};

GmailConfiguration.prototype.getConfig = function(client_id, callback) {
	var params = [ client_id, 'google' ];
	try {
		ssoConfig.getSSOConfigByTenant(params, function(err, res) {
			if (!err) {
				if (typeof (res.config) == 'undefined') {
					var err = new Error("Invalid tenant");
					err.status = 401;
					return callback(err, null);
				}

				return callback(err, res);
			} else {
				return callback(err, null);
			}
		});
	} catch (error) {
		return callback(error, null);
	}
};

module.exports = GmailConfiguration;