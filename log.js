var winston = require('winston');
var logger = new(winston.Logger)({
    transports: [
        new(winston.transports.File)({
            filename: 'access.log'
        })
    ]
});
module.exports = logger;
