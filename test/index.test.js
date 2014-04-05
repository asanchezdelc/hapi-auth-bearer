var Stream = require('stream');
var Hapi = require('hapi');
var Hawk = require('hawk');
var assert = require('assert');

describe('Bearer', function() {

  var credentials = {
    // token
    'rpaxn39848xrunpaw3489ruxnpa98w4rxn': {
      token: 'rpaxn39848xrunpaw3489ruxnpa98w4rxn'
    },
    // secret (for base64)
    'werxhqb98': {
      secret: 'werxhqb98',
      token: 'rpaxn39848xrunpaw3489ruxnpa98w4rxn'
    },
    // forces an error to be thrown
    'error': {
      token: 'error',
      err: Hapi.error.internal('boom')
    }
  };

  var validateFunc = function (id, callback) {
    if (credentials[id]) {
      return callback(credentials[id].err, credentials[id]);
    }

    return callback(null, null);
  };

  var validateBase64Func = function (id, token, callback) {
    if (credentials[id]) {
      return callback(credentials[id].err, credentials[id]);
    }

    return callback(null, null);
  };

  var tokenHeader = function(token) {
    return 'Bearer ' + credentials[token].token;
  };

  var base64Header = function(secret) {
    return 'Bearer ' + new Buffer(secret + ':' + credentials[secret].token).toString('base64');
  };

  var handler = function (request, reply) {
    reply('Success');
  };


  var server = new Hapi.Server();
  before(function(done) {
    server.pack.require('../', function (err) {
      assert.ifError(err);

      server.auth.strategy('bearer', 'bearer', { validateFunc: validateFunc });
      server.auth.strategy('bearer-base64', 'bearer', { validateFunc: validateBase64Func, base64: true });

      server.route([
        { method: 'POST', path: '/bearer', handler: handler, config: { auth: 'bearer' } },
        { method: 'GET', path: '/bearer', handler: handler, config: { auth: 'bearer' } },
        { method: 'POST', path: '/bearer-base64', handler: handler, config: { auth: 'bearer-base64' } }
      ]);

      done();
    });
  });


  describe('token', function() {
    it('returns a reply on successful auth', function (done) {
      var request = { method: 'POST', url: 'http://example.com:8080/bearer', headers: { authorization: tokenHeader('rpaxn39848xrunpaw3489ruxnpa98w4rxn') } };

      server.inject(request, function (res) {

        assert.equal(res.statusCode, 200);
        assert.equal(res.result, 'Success');
        done();
      });
    });

    it('returns a reply with query token on success auth', function(done) {
      var request = { method: 'GET', url: 'http://example.com:8080/bearer?access_token=rpaxn39848xrunpaw3489ruxnpa98w4rxn' };

      server.inject(request, function (res) {
        assert.equal(res.statusCode, 200);
        assert.equal(res.result, 'Success');
        done();
      });
    });

    it('returns a reply with query token on success auth', function(done) {
      var request = { 
        method: 'POST', 
        url: 'http://example.com:8080/bearer',
        payload: { access_token: "rpaxn39848xrunpaw3489ruxnpa98w4rxn"}          
      };
      server.inject(request, function (res) {   
        assert.equal(res.statusCode, 200);
        assert.equal(res.result, 'Success');
        done();
      });
    });

    it('returns a reply on failed auth with no access token', function(done) {
      var request = { method: 'GET', url: 'http://example.com:8080/bearer' };

      server.inject(request, function (res) {
        assert.equal(res.statusCode, 401);
        assert.equal(res.result.message, 'Missing authentication');
        assert.equal(res.headers['www-authenticate'], 'Bearer');
        done();
      });
    });

    it('returns a reply on failed with invalid token', function(done) {
      var request = { method: 'GET', url: 'http://example.com:8080/bearer?access_token=rpaxn39848xrunpaw3488w4rxn' };
      
      server.inject(request, function (res) {
        assert.equal(res.statusCode, 401);
        assert.equal(res.result.message, 'Invalid token');
        done();
      });
    });


    it('returns a reply on failed auth (with no authorization header)', function (done) {
      var request = { method: 'POST', url: 'http://example.com:8080/bearer' };

      server.inject(request, function (res) {
        assert.equal(res.statusCode, 401);
        assert.equal(res.result.message, 'Missing authentication');
        assert.equal(res.headers['www-authenticate'], 'Bearer');
        done();
      });
    });

    it('returns a reply on failed auth (with invalid format)', function (done) {
      var request = { method: 'POST', url: 'http://example.com:8080/bearer', headers: { authorization: 'Bearer' } };

      server.inject(request, function (res) {
        assert.equal(res.statusCode, 400);
        assert.equal(res.result.message, 'Bad HTTP authentication header format');
        done();
      });
    });

    it('returns a reply on failed auth (when authorization header value doesn\'t contain Bearer)', function (done) {
      var request = { method: 'POST', url: 'http://example.com:8080/bearer', headers: { authorization: 'Basic rpaxn39848xrunpaw3489ruxnpa98w4rxn' } };

      server.inject(request, function (res) {
        assert.equal(res.statusCode, 401);
        assert.equal(res.result.message, 'Missing authentication');
        done();
      });
    });

    it('returns a reply on failed auth (when credentials are invalid)', function (done) {
      var request = { method: 'POST', url: 'http://example.com:8080/bearer', headers: { authorization: 'Bearer tokenThatDoesNotExist' } };

      server.inject(request, function (res) {
        assert.equal(res.statusCode, 401);
        assert.equal(res.result.message, 'Invalid token');
        done();
      });
    });

    it('returns a reply on failed auth (an error is thrown)', function (done) {
      var request = { method: 'POST', url: 'http://example.com:8080/bearer', headers: { authorization: tokenHeader('error') } };

      server.inject(request, function (res) {
        assert.equal(res.statusCode, 500);
        assert.equal(res.result.message, 'An internal server error occurred');
        done();
      });
    });
  });

  describe('base64', function() {
    it('returns a reply on successful auth', function (done) {
      var request = { method: 'POST', url: 'http://example.com:8080/bearer-base64', headers: { authorization: base64Header('werxhqb98') } };

      server.inject(request, function (res) {
        assert.equal(res.statusCode, 200);
        assert.equal(res.result, 'Success');
        done();
      });
    });

    it('returns a reply on failed auth (with no authorization header)', function (done) {
      var request = { method: 'POST', url: 'http://example.com:8080/bearer-base64' };

      server.inject(request, function (res) {
        assert.equal(res.statusCode, 401);
        assert.equal(res.result.message, 'Missing authentication');
        assert.equal(res.headers['www-authenticate'], 'Bearer');
        done();
      });
    });

    it('returns a reply on failed auth (with invalid format)', function (done) {
      var request = { method: 'POST', url: 'http://example.com:8080/bearer-base64', headers: { authorization: 'Bearer' } };

      server.inject(request, function (res) {
        assert.equal(res.statusCode, 400);
        assert.equal(res.result.message, 'Bad HTTP authentication header format');
        done();
      });
    });

    it('returns a reply on failed auth (when authorization header value doesn\'t contain Bearer)', function (done) {
      var request = { method: 'POST', url: 'http://example.com:8080/bearer-base64', headers: { authorization: 'Basic werxhqb98' } };

      server.inject(request, function (res) {
        assert.equal(res.statusCode, 401);
        assert.equal(res.result.message, 'Missing authentication');
        done();
      });
    });

    it('returns a reply on failed auth (bad base64 encoded header)', function (done) {
      var header = 'Bearer ' + new Buffer('i:am:invalid').toString('base64');
      var request = { method: 'POST', url: 'http://example.com:8080/bearer-base64', headers: { authorization: header } };

      server.inject(request, function (res) {
        assert.equal(res.statusCode, 400);
        assert.equal(res.result.message, 'Bad HTTP authentication token value format');
        done();
      });
    });

    it('returns a reply on failed auth (when credentials are invalid)', function (done) {
      var request = { method: 'POST', url: 'http://example.com:8080/bearer-base64', headers: { authorization: 'Bearer tokenThatDoesNotExist' } };

      server.inject(request, function (res) {
        assert.equal(res.statusCode, 401);
        assert.equal(res.result.message, 'Invalid token');
        done();
      });
    });

    it('returns a reply on failed auth (an error is thrown)', function (done) {
      var request = { method: 'POST', url: 'http://example.com:8080/bearer-base64', headers: { authorization: base64Header('error') } };

      server.inject(request, function (res) {
        assert.equal(res.statusCode, 500);
        assert.equal(res.result.message, 'An internal server error occurred');
        done();
      });
    });
  });
});