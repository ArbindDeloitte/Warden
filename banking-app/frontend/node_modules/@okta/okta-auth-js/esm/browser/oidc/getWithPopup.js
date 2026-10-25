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
 */

import { __rest } from '../_virtual/_tslib.js';
import AuthSdkError from '../errors/AuthSdkError.js';
import '../errors/WWWAuthError.js';
import { clone } from '../util/object.js';
import { getToken } from './getToken.js';
import { loadPopup } from './util/browser.js';
import { generateState } from './util/oauth.js';
import '../http/request.js';
import 'tiny-emitter';
import 'js-cookie';
import 'cross-fetch';
import './types/Token.js';

function getWithPopup(sdk, options) {
    if (arguments.length > 2) {
        return Promise.reject(new AuthSdkError('As of version 3.0, "getWithPopup" takes only a single set of options'));
    }
    const { initialPath } = options, params = __rest(options, ["initialPath"]);
    const popupWindow = loadPopup(initialPath !== null && initialPath !== void 0 ? initialPath : '/', params);
    options = clone(params) || {};
    Object.assign(params, {
        display: 'popup',
        responseMode: 'okta_post_message',
        popupWindow
    });
    return getToken(sdk, params);
}
function getWithIDPPopup(sdk, options) {
    try {
        if (!BroadcastChannel) {
            throw new AuthSdkError('Modern browser with `BroadcastChannel` support is required to use this method');
        }
        if (!options.redirectUri) {
            throw new AuthSdkError('`redirectUri` is a required param for `getWithIDPPopup`');
        }
        if (!options.state) {
            options.state = generateState();
        }
        const popupWindow = loadPopup('/', options);
        const channel = new BroadcastChannel(`popup-callback:${options.state}`);
        options = clone(options) || {};
        Object.assign(options, {
            display: 'popup',
            responseMode: 'query',
            popupWindow,
            idpPopup: true,
            channel,
        });
        let cancelPromise;
        const promise = new Promise((resolve, reject) => {
            cancelPromise = reject;
            return getToken(sdk, options)
                .then((res) => resolve(res))
                .catch(err => reject(err));
        });
        const cancel = () => {
            channel.close();
            cancelPromise(new AuthSdkError('Popup flow canceled'));
        };
        return {
            promise,
            cancel
        };
    }
    catch (err) {
        return {
            promise: Promise.reject(err),
            cancel: () => { }
        };
    }
}

export { getWithIDPPopup, getWithPopup };
//# sourceMappingURL=getWithPopup.js.map
