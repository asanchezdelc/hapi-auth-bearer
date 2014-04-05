var boom = require('boom');
var hoek = require('hoek');

/**
 * Simple Bearer auth token strategy.
 *
 * If `options.base64` is set to `true`, then it expects a base64 encoded value of SECRET:TOKEN, otherwise
 * it expects the Bearer value to just be the token.
 *    i.e.) Bearer NTJlYjRmZmRmM2M3MjNmZjA1MTEwYmYxOjk5ZWQyZjdmMWRiNjBiZDBlNGY1ZjQ4ZjRhMWVhNWVjMmE4NzU2ZmU=
 *
 *
 * @param server
 * @param {Object} options
 *
 * @returns {{authenticate: Function}}
 */
var bearerScheme = function bearerScheme(server, options) {
  hoek.assert(options && 'object' === typeof options, 'Missing Bearer auth strategy options');

  hoek.assert(
    options && 'function' === typeof options.validateFunc,
    'options.validateFunc must be a valid function in Bearer scheme'
  );

  options.base64 = options.base64 || false;

  return {
    authenticate: function (request, reply) {
      var req = request.raw.req;
      var token, scheme;

      if(req.headers && req.headers.authorization) {
        var parts = req.headers.authorization.split(/\s+/);
        if (parts.length == 2) {            
            var credentials = parts[1];
            scheme = parts[0];
            
          if (/^Bearer$/i.test(scheme)) {
            token = credentials;
          } 
        } else {
          return reply(boom.badRequest('Bad HTTP authentication header format'));
        }
      }
      
      if (request.payload && request.payload.access_token) {
        if (token) { return reply(boom.unauthorized(null, 'Bearer')); }
        token = request.payload.access_token;
      }

      if (request.query && request.query.access_token) {
        if (token) { return reply(boom.unauthorized(null, 'Bearer')); }
        token = request.query.access_token;
      }

      if(!token) return reply(boom.unauthorized(null, 'Bearer'));


      var createCallback = function(secret, token) {
        return function (err, credentials) {
          if (err) {
            return reply(err, { credentials: credentials, log: { tags: ['auth', 'bearer-auth'], data: err } });
          }
          if (!credentials || (token && (!credentials.token || credentials.token !== token))) {
            return reply(boom.unauthorized('Invalid token', 'Bearer'), { credentials: credentials });
          }

          return reply(null, { credentials: credentials });
        }
      };

      if (options.base64) {
        var tokenParts = new Buffer(token || '', 'base64').toString('utf8').split(':');
        if (tokenParts.length !== 2) {
          return reply(boom.badRequest('Bad HTTP authentication token value format'));
        }

        return options.validateFunc(tokenParts[0], tokenParts[1], createCallback(tokenParts[0], tokenParts[1]));
      } else {
        return options.validateFunc(token, createCallback(null, token));
      }
    }
  };
};


exports.register = function (plugin, options, next) {
  plugin.auth.scheme('bearer', bearerScheme);
  next();
};