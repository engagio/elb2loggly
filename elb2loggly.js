var aws = require('aws-sdk');
var s3 = new aws.S3({apiVersion: '2006-03-01'});
var _ = require('lodash');
var async = require('async');
var request = require('request');
var Transform = require('stream').Transform;
var csv = require('csv-streamify');
var JSONStream = require('JSONStream');
var zlib = require('zlib');

// Set LOGGLY_TOKEN to your Loggly customer token. It will look something like this:
// LOGGLY_TOKEN = 'ea5058ee-d62d-4faa-8388-058646faa747'
// Preferably, you should set the tag 'loggly-customer-tag' on the S3 bucket.

// Optionally set a LOGGLY_TAG if you want to tag these logs in a certain way. For example:
// LOGGLY_TAG = 'aws-elb-logs'
// Preferably, you should set the 'loggly-tag' on the S3 bucket.

var LOGGLY_URL_BASE = 'https://logs-01.loggly.com/bulk/';
var BUCKET_LOGGLY_TOKEN_NAME = 'loggly-customer-token';
var BUCKET_LOGGLY_TAG_NAME = 'loggly-tag';
var BUCKET_LOGGLY_PRIVATE_URL_PARAMS_NAME = 'elb2loggly-private-url-params';

var LOGGLY_URL = null;
var DEFAULT_LOGGLY_URL = null;

/* eslint-disable no-undef */
if (typeof LOGGLY_TOKEN !== 'undefined') {
  DEFAULT_LOGGLY_URL = LOGGLY_URL_BASE + LOGGLY_TOKEN;

  if (typeof LOGGLY_TAG !== 'undefined') {
    DEFAULT_LOGGLY_URL += '/tag/' + LOGGLY_TAG;
  }
}
/* eslint-enable no-undef */

if (DEFAULT_LOGGLY_URL) {
  console.log('Loading elb2loggly, default Loggly endpoint: ' + DEFAULT_LOGGLY_URL);
} else {
  console.log(
    'Loading elb2loggly, NO default Loggly endpoint, must be set in bucket tag ' + BUCKET_LOGGLY_TOKEN_NAME);
}

// AWS logs contain the following fields: (Note: a couple are parsed from within the field.)
// http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/access-log-collection.html
var COLUMNS = [
  'type', // 0
  'timestamp', // 1
  'elb', // 2
  'client_ip', // 3
  'client_port', // 4 - split from client
  'backend', // 5
  'backend_port', // 6
  'request_processing_time', // 7
  'backend_processing_time', // 8
  'response_processing_time', // 9
  'elb_status_code', // 10
  'backend_status_code', // 11
  'received_bytes', // 12
  'sent_bytes', // 13
  'request_method', // 14 - Split from request
  'request_url', // 15 - Split from request
  'request_query_params', // 16 - Split from request
  'user_agent', // 17
  'ssl_cipher', // 18
  'ssl_protocol', // 19
  'target_group_arn', // 20
  'trace_id', // 21
  'empty' //22
];

// The following column indexes will be turned into numbers so that
// we can filter within loggly
var NUMERIC_COL_INDEX = [
  7,
  8,
  9,
  12,
  13
];

// A counter for the total number of events parsed
var eventsParsed = 0;

// Private query parameters that should be removed/obscured from the URL
var PRIVATE_URL_PARAMS = [];
var PRIVATE_URL_PARAMS_MAX_LENGTH = [];

// Obscures the provided parameter in the URL
// Returns the URL with the provided parameter obscured
var obscureURLParameter = function(url, parameter, obscureLength) {
    // prefer to use l.search if you have a location/link object
  var urlparts = url.split('?');
  if (urlparts.length >= 2) {
    var prefix = encodeURIComponent(parameter) + '=';
    var pars = urlparts[1].split(/[&;]/g);

        // reverse iteration as may be destructive
    for (var i = pars.length; i-- > 0;) {
            // If the parameter starts with the encoded prefix
      if (pars[i].lastIndexOf(prefix, 0) !== -1) {
        if (obscureLength > 0 && pars[i].length > obscureLength) {
            // If the total length of of the parameter is greater than
            // obscureLength we only take the left most characters
          pars[i] = pars[i].substring(0, prefix.length + obscureLength) + "...";
        } else {
            // Otherwise we just remove the parameter
          pars.splice(i, 1);
        }
      }
    }

    url = urlparts[0] + '?' + pars.join('&');
  }

  return url;
};

// Parse elb log into component parts.
var parseS3Log = function(data, encoding, done) {
  var originalData = data;

  // The trace_id field is optional
  if (data.length === 1) {
    done();
  }
  else if (data.length === 17 || data.length === 18 || data.length === 19) {
      // Split clientip:port and backendip:port at index 3,4
      // We need to be careful here because of potential 5xx errors which may not include
      // backend:port
    if (data[4].indexOf(':') > -1) {
        // If the field contains a colon we perform the normal split to get ip and port
      data.splice(4, 1, data[4].split(':'));
    } else {
        // We may get here if there was a 5xx error
        // We will add 'dash' place holders for the missing data
        // This is common for Apache logs when a field is blank, it is also more consistent with
        // the original ELB data
      data.splice(4, 1, '-', '-');
    }

      // client:port
    data.splice(3, 1, data[3].split(':'));

      // Ensure the data is flat
    data = _.flatten(data);

      // Pull the method from the request.  (WTF on Amazon's decision to keep these as one string.)
    var initialRequestPosition = 14
    var urlMash = data[initialRequestPosition];
    data.splice(initialRequestPosition, 1);
      // Ensure the data is flat
    data = _.flatten(data);

      // Split the url, the 2 parameter gives us only the last 2
      // e.g. Split POST https://secure.echoboxapp.com:443/api/authtest HTTP/1.1
      // into [0] - POST, [1] - https://secure.echoboxapp.com:443/api/authtest
    urlMash = urlMash.split(' ', 2);
    var requestMethod = urlMash[0];
    var requestUrl = urlMash[1];

      // Remove any private URL query parameters
    _.each(PRIVATE_URL_PARAMS, function(paramToRemove, paramIndex) {
      requestUrl = obscureURLParameter(requestUrl, paramToRemove, PRIVATE_URL_PARAMS_MAX_LENGTH[paramIndex]);
    });

      // Strip the query parameters into a separate field if any exist
    var requestParams = "";
    if (requestUrl.indexOf('?') !== -1) {
      requestParams = requestUrl.substring(requestUrl.indexOf('?') + 1, requestUrl.length);
      requestUrl = requestUrl.substring(0, requestUrl.indexOf('?'));
    }

      // Add the url request back into data array at the original position
    data.splice(initialRequestPosition, 0, requestParams);
    data.splice(initialRequestPosition, 0, requestUrl);
    data.splice(initialRequestPosition, 0, requestMethod);
      // Ensure the data is flat
    data = _.flatten(data);

      // Parse the numeric columns to floats
    _.each(NUMERIC_COL_INDEX, function(colIndex) {
      data[colIndex] = parseFloat(data[colIndex]);
    });

    if (data.length === COLUMNS.length) {
      this.push(_.zipObject(COLUMNS, data));
      eventsParsed++;
    } else {
      /* eslint-disable camelcase */
      var errorLog = {
        timestamp: originalData[1],
        elb: originalData[2],
        elb_status_code: originalData[8],
        error: 'ELB log length: ' + originalData.length + ' did not match COLUMNS length ' + COLUMNS.length
      };
      /* eslint-enable camelcase */

      this.push(errorLog);
        // Log an error including the line that was excluded
      console.error('ELB log length ' + data.length + ' did not match COLUMNS length ' + COLUMNS.length + ". " + data.join(" "));
    }

    done();
  } else {
      // Record a useful error in the lambda logs that something was wrong with the input data
    done("Expecting 17 or 18 fields, actual fields " + data.length + " " + JSON.stringify(data));
  }
};

exports.handler = function(event, context, callback) {
   // A useful line for debugging, add a version number to see which version ran in lambda
  console.log('Running lambda event handler.');

   // Get the object from the event and show its content type
  var bucket = event.Records[0].s3.bucket.name;
  var key = event.Records[0].s3.object.key;
  var size = event.Records[0].s3.object.size;

  if (size === 0) {
    console.log('S3ToLoggly skipping object of size zero');
  } else {
       // Download the logfile from S3, and upload to loggly.
    async.waterfall([
      function buckettags(next) {
        var params = {
          Bucket: bucket /* required */
        };

        s3.getBucketTagging(params, function(err, data) {
          if (err) {
            next(err);
            console.log(err, err.stack);
          } else {
              // Get an array of bucket tags
            var s3tag = _.zipObject(_.map(data.TagSet, 'Key'),
             _.map(data.TagSet, 'Value'));

              // If the 'token' tag is set we use that
            if (s3tag[BUCKET_LOGGLY_TOKEN_NAME]) {
              LOGGLY_URL = LOGGLY_URL_BASE + s3tag[BUCKET_LOGGLY_TOKEN_NAME];

                // If the 'loggly tag' tag is set we use that
              if (s3tag[BUCKET_LOGGLY_TAG_NAME]) {
                LOGGLY_URL += '/tag/' + s3tag[BUCKET_LOGGLY_TAG_NAME];
              }
            } else {
              LOGGLY_URL = DEFAULT_LOGGLY_URL;
            }
          }

            // If the 'private url params' tag set we parse that
          if (s3tag[BUCKET_LOGGLY_PRIVATE_URL_PARAMS_NAME]) {
              // First we split on double forward slash
            var privateParamEntries = s3tag[BUCKET_LOGGLY_PRIVATE_URL_PARAMS_NAME].split(/\/\//g);
            _.each(privateParamEntries, function(entry) {
                // The parameter name and max length is separated by a single forward slash
              var entrySplit = entry.split(/\//g);
              var paramName = entrySplit[0];
              var paramMaxLength = parseInt(entrySplit[1], 10);
              console.log('Private url parameter ' + paramName + ' will be obscured with max length ' + paramMaxLength + '.');
              PRIVATE_URL_PARAMS.push(paramName);
              PRIVATE_URL_PARAMS_MAX_LENGTH.push(paramMaxLength);
            });
          }

          if (LOGGLY_URL) {
            next();
          } else {
            next('No Loggly customer token. Set S3 bucket tag ' + BUCKET_LOGGLY_TOKEN_NAME);
          }
        });
      },

      function download(next) {
          // Download the image from S3 into a buffer.
        s3.getObject({
          Bucket: bucket,
          Key: key
        },
        next);
      },

      function upload(data, next) {
        // csv-streamify does not properly handle strings with escaped double quotes.
        // So: "hello \"world\"" is not parsed as one string. To handle this, rewrite
        // the \" as \' so the are ignored by the csv-streamify parser.
        // Note: This only works because the AWS log should not have \" anywhere except the
        // user agent field, and only in quoted strings.
        var doubleToSingleQuote = function(data, encoding, done) {
          var newStr = data.toString().replace(/\\"/g, '\\\'');
          this.push(newStr);
          done();
        };

        var gunzip = zlib.createGunzip();
        var csvToJson = csv({objectMode: true, delimiter: ' '});
        var transquote = new Transform({objectMode: true});
        transquote._transform = doubleToSingleQuote;
        var parser = new Transform({objectMode: true});
        parser._transform = parseS3Log;
        var jsonToStrings = JSONStream.stringify(false);
        var bufferStream = new Transform();

        bufferStream.push(data.Body);
        bufferStream.end();

        console.log('Using Loggly endpoint: ' + LOGGLY_URL);

        bufferStream
         .pipe(gunzip)
         .pipe(transquote)
         .pipe(csvToJson)
         .pipe(parser)
         .pipe(jsonToStrings)
         .pipe(request.post(LOGGLY_URL))
         .on('error', function(err) {
           next(err);
         }).on('end', function() {
           next();
         });
      }
    ], function(err) {
      if (err) {
        console.error(
            'Unable to read ' + bucket + '/' + key +
            ' and upload to loggly' +
            ' due to an error: ' + err
            );
        callback(err);
      } else {
        console.log(
            'Successfully uploaded ' + bucket + '/' + key +
            ' to ' + LOGGLY_URL + ". Parsed " + eventsParsed + " events."
            );
        callback();
      }
    });
  }
};
