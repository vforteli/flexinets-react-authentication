import decode from 'jwt-decode';
import axios from 'axios';
import qs from 'qs';

//let AUTH_BASE_URL = 'http://localhosdt:65138';     // todo this should be configurable
let AUTH_BASE_URL = 'https://authentication.flexinets.se';
const STORAGE_KEY = 'react_token';

axios.defaults.validateStatus = (status) => { return status >= 200 && status < 500; };
axios.interceptors.request.use(async config => AuthenticationService.authInterceptor(config));

let token = null;
let currentUser = null;
let refreshPromise = null;

export default class AuthenticationService {
    static setBaseUrl(url) { AUTH_BASE_URL = url; }
    static getLoginUrl() { return `${AUTH_BASE_URL}/token`; }
    static getLogoutUrl() { return `${AUTH_BASE_URL}/logout`; }
    static getAccountUrl() { return `${AUTH_BASE_URL}/api/account/`; }


    static async login(username, password) {
        this.clearTokenContext();
        const response = await axios({
            method: 'post',
            url: this.getLoginUrl(),
            data: qs.stringify({
                'grant_type': 'password',
                'username': username,
                'password': password
            }),
            config: { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
        });
        if (response.status === 200) {
            this.setJwtToken(response.data);
        }
        return response;
    }


    /**
     * Begin password reset for email
     * @param {string} email 
     * @param {string} returnUrl Domain part of return url
     */
    static async beginReset(email, returnUrl) {
        const response = await axios({
            method: 'post',
            url: this.getAccountUrl() + 'resetpassword/beginreset/',
            data: {
                EmailAddress: email,
                ReturnUrl: returnUrl
            }
        });
        return response;
    }


    /**
     * Complete a password reset request
     * @param {string} password 
     * @param {string} passwordConfirm 
     * @param {string} resetId 
     */
    static async completeReset(password, passwordConfirm, resetId) {
        return await axios({
            method: 'post',
            url: this.getAccountUrl() + 'resetpassword/completereset/',
            data: {
                password: password,
                passwordConfirm: passwordConfirm,
                resetId: resetId
            }
        });
    }


    /**
     * Validate a reset token
     * @param {string} resetId 
     */
    static async validateResetToken(resetId) {
        return await axios.get(`${this.getAccountUrl()}resetpassword/validateresettoken/${resetId}`);
    }


    /**
     * Authinterceptor for axios
     * @param {*} config 
     */
    static async  authInterceptor(config) {
        // With credentials must be enabled for requests to login and logout url, because the refresh token is stored as an http only cookie
        if (config.url.indexOf(this.getLoginUrl()) >= 0 || config.url.indexOf(this.getLogoutUrl()) >= 0) {
            config.withCredentials = true;
        }
        else {
            const accessToken = await this.getRefreshedAccessToken();
            if (accessToken !== null) {
                config.headers.authorization = `Bearer ${accessToken}`;
            }
        }
        return config;
    }


    static async  logout() {
        this.clearTokenContext();
        await axios.post(this.getLogoutUrl());
        console.debug('Logged out');
    }


    /**
     * Check if a user is logged in.
     * Assumed to be logged in if a token exists, and the refresh token has not expired
     */
    static isLoggedIn() {
        const token = this.getJwtToken();
        return token !== null && token.refresh_token_expires > new Date().getTime() / 1000;
    }


    static getCurrentUser() {
        if (currentUser === null) {
            const token = this.getJwtToken();
            if (token !== null) {
                try {
                    const claims = decode(token.access_token);
                    currentUser = {
                        EmailAddress: claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'],
                        FirstName: claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname'],
                        LastName: claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname'],
                        Roles: claims['http://schemas.microsoft.com/ws/2008/06/identity/claims/role'],
                        isInRole: function (role) { return this.Roles.indexOf(role) >= 0; },
                        settings: {}
                    };
                }
                catch (error) {
                    console.debug('unable to parse token');
                }
            }
        }
        return currentUser;
    }


    /**
     * Get an access token which has been refreshed if expired
     */
    static async getRefreshedAccessToken() {
        const token = this.getJwtToken();
        if (token !== null) {
            if (this.isJwtTokenExpired(token.access_token)) {
                console.debug('Token has expired, start refresh maybe');
                const result = await this.refreshAccessToken();
                console.debug(`token refresh result ${result}`);
            }
            return this.getJwtToken().access_token;    // test stuff
        }
        return null;
    }


    /**
     * Check if an email address is available for an admin account
     * @param {any} email 
     */
    static async checkEmailAvailability(email) {
        const response = await axios.get(`${AUTH_BASE_URL}/api/checkemailavailability?email=${email}`);
        return response.data.available;
    }



    /**
     * Save the token to localStorage
     * @param {string} jwtTokenJson
     */
    static setJwtToken(jwtTokenJson) {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(jwtTokenJson));
        token = jwtTokenJson;
    }


    /**
     * Get the token from localStorage or variable if available
     */
    static getJwtToken() {
        if (token === null) {
            console.debug('getting token from localstorage');
            token = JSON.parse(localStorage.getItem(STORAGE_KEY));
        }
        return token;
    }


    /**
     * Refresh access token
     */
    static async refreshAccessToken() {
        console.debug('Refreshing access token');

        if (refreshPromise === null) {
            console.debug('No pending access token refresh, starting new');
            refreshPromise = axios({
                method: 'post',
                url: this.getLoginUrl(),
                data: qs.stringify({ 'grant_type': 'refresh_token' }),
                config: { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
            }).then(response => {
                console.debug('Refreshed access token');
                this.setJwtToken(response.data);
                return true;
            }).catch(error => {
                console.debug(error);
                if (error.response.data.error === 'invalid_grant') {
                    console.debug('Refresh token expired or invalidated');
                    this.clearTokenContext();
                    return false;
                }
            }).finally(() => refreshPromise = null);
        }

        return refreshPromise;
    }


    /**
    * Clear the local token context
    */
    static clearTokenContext() {
        console.debug('clearing token context');
        localStorage.removeItem(STORAGE_KEY);
        token = null;
        currentUser = null;
    }


    /**
     * Check if an access token has expired
     * @param {string} jwtToken
     */
    static isJwtTokenExpired(jwtToken) {
        const token = decode(jwtToken);
        if (!token.exp) { return null; }

        const expirationDate = new Date(0);
        expirationDate.setUTCSeconds(token.exp);

        return expirationDate < new Date();
    }
}
