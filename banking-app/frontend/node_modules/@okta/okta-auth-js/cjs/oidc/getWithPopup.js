"use strict";

exports.getWithIDPPopup = getWithIDPPopup;
exports.getWithPopup = getWithPopup;
var _errors = require("../errors");
var _util = require("../util");
var _getToken = require("./getToken");
var _util2 = require("./util");
/*!
 * Copyright (c) 2015-present, Okta, Inc. and/or its affiliates. All rights reserved.
 * The Okta software accompanied by this notice is provided pursuant to the Apache License, Version 2.0 (the "License.")
 *
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 *
 */

function getWithPopup(sdk, options) {
  if (arguments.length > 2) {
    return Promise.reject(new _errors.AuthSdkError('As of version 3.0, "getWithPopup" takes only a single set of options'));
  }
  const {
    initialPath,
    ...params
  } = options;

  // some browsers (safari, firefox) block popup if it's initialed from an async process
  // here we create the popup window immediately after user interaction
  // then redirect to the /authorize endpoint when the requestUrl is available
  const popupWindow = (0, _util2.loadPopup)(initialPath ?? '/', params);
  options = (0, _util.clone)(params) || {};
  Object.assign(params, {
    display: 'popup',
    responseMode: 'okta_post_message',
    popupWindow
  });
  return (0, _getToken.getToken)(sdk, params);
}
function getWithIDPPopup(sdk, options) {
  try {
    // eslint-disable-next-line compat/compat
    if (!BroadcastChannel) {
      throw new _errors.AuthSdkError('Modern browser with `BroadcastChannel` support is required to use this method');
    }
    if (!options.redirectUri) {
      throw new _errors.AuthSdkError('`redirectUri` is a required param for `getWithIDPPopup`');
    }
    if (!options.state) {
      options.state = (0, _util2.generateState)();
    }

    // some browsers (safari, firefox) block popup if it's initialed from an async process
    // here we create the popup window immediately after user interaction
    // then redirect to the /authorize endpoint when the requestUrl is available
    const popupWindow = (0, _util2.loadPopup)('/', options);
    // eslint-disable-next-line compat/compat
    const channel = new BroadcastChannel(`popup-callback:${options.state}`);
    options = (0, _util.clone)(options) || {};
    Object.assign(options, {
      display: 'popup',
      responseMode: 'query',
      popupWindow,
      idpPopup: true,
      channel
    });
    let cancelPromise;
    const promise = new Promise((resolve, reject) => {
      cancelPromise = reject;
      return (0, _getToken.getToken)(sdk, options).then(res => resolve(res)).catch(err => reject(err));
    });
    const cancel = () => {
      channel.close();
      cancelPromise(new _errors.AuthSdkError('Popup flow canceled'));
    };
    return {
      promise,
      cancel
    };
  } catch (err) {
    return {
      promise: Promise.reject(err),
      cancel: () => {} // noop, no need to for method when error is thrown
    };
  }
}
//# sourceMappingURL=getWithPopup.js.map