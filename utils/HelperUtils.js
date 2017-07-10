const crypto = require('crypto');
const CLIENT_KEY_HASH = "$GooruCLIENTKeyHash$";
const logger = require('../log');

module.exports.encryptClientKey = function(key) {
  return encrypt(CLIENT_KEY_HASH + key);  
};

function encrypt(text) {
    try {
        var shasum = crypto.createHash('sha1');
        shasum.update(text);
        var data = shasum.digest();
        return new Buffer(data).toString('base64');
    } catch(err) { 
        logger.error(err);
    }
   return null;
}
