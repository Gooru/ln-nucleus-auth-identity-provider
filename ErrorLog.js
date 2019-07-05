var winston = require('winston');
require('winston-daily-rotate-file');

var transport = new (winston.transports.DailyRotateFile)({
	filename : './log',
	datePattern : 'error-yyyy-MM-dd.',
	prepend : true,
	level : 'error'
});

var logger = new (winston.Logger)({
	transports : [ transport ]
});

module.exports = logger;
