"use strict";

var _interopRequireDefault = require("@babel/runtime/helpers/interopRequireDefault");
exports.generateRequestFnFromLinks = generateRequestFnFromLinks;
exports.sendRequest = sendRequest;
var _Base = _interopRequireDefault(require("./transactions/Base"));
var _http = require("../http");
var _errors = require("../errors");
/* eslint-disable complexity */
async function sendRequest(oktaAuth, options, TransactionClass = _Base.default) {
  const {
    accessToken: accessTokenObj
  } = oktaAuth.tokenManager.getTokensSync();
  const atToken = options.accessToken || accessTokenObj;
  const issuer = oktaAuth.getIssuerOrigin();
  const {
    url,
    method,
    payload
  } = options;
  const requestUrl = url.startsWith(issuer) ? url : `${issuer}${url}`;
  if (!atToken) {
    throw new _errors.AuthSdkError('AccessToken is required to request MyAccount API endpoints.');
  }
  let accessToken = atToken;
  const httpOptions = {
    headers: {
      'Accept': '*/*;okta-version=1.0.0'
    },
    url: requestUrl,
    method,
    ...(payload && {
      args: payload
    })
  };
  if (oktaAuth.options.dpop) {
    if (typeof accessToken === 'string') {
      throw new _errors.AuthSdkError('AccessToken object must be provided when using dpop');
    }
    const {
      Authorization,
      Dpop
    } = await oktaAuth.getDPoPAuthorizationHeaders({
      method,
      url: requestUrl,
      accessToken
    });
    httpOptions.headers.Authorization = Authorization;
    httpOptions.headers.Dpop = Dpop;
  } else {
    accessToken = typeof accessToken === 'string' ? accessToken : accessToken.accessToken;
    httpOptions.accessToken = accessToken;
  }
  const res = await (0, _http.httpRequest)(oktaAuth, httpOptions);
  let ret;
  if (Array.isArray(res)) {
    ret = res.map(item => new TransactionClass(oktaAuth, {
      res: item,
      accessToken
    }));
  } else {
    ret = new TransactionClass(oktaAuth, {
      res,
      accessToken
    });
  }
  return ret;
}
/* eslint-enable complexity */

function generateRequestFnFromLinks({
  oktaAuth,
  accessToken,
  methodName,
  links
}, TransactionClass = _Base.default) {
  for (const method of ['GET', 'POST', 'PUT', 'DELETE']) {
    if (method.toLowerCase() === methodName) {
      const link = links.self;
      return async payload => sendRequest(oktaAuth, {
        accessToken,
        url: link.href,
        method,
        payload
      }, TransactionClass);
    }
  }
  const link = links[methodName];
  if (!link) {
    throw new _errors.AuthSdkError(`No link is found with methodName: ${methodName}`);
  }
  return async payload => sendRequest(oktaAuth, {
    accessToken,
    url: link.href,
    method: link.hints.allow[0],
    payload
  }, TransactionClass);
}
//# sourceMappingURL=request.js.map