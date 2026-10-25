import { OktaAuthOAuthInterface, TokenParams, TokenResponse } from './types';
export declare function getWithPopup(sdk: OktaAuthOAuthInterface, options: TokenParams & {
    initialPath?: string;
}): Promise<TokenResponse>;
export declare function getWithIDPPopup(sdk: OktaAuthOAuthInterface, options: Omit<TokenParams, 'redirectUri'> & {
    redirectUri: string;
}): {
    cancel: () => void;
    promise: Promise<TokenResponse>;
};
