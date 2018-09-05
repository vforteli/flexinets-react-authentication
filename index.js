import decode from 'jwt-decode';
import axios from 'axios';
import qs from 'qs';

// todo this entire module should be wrapped more neatly...
// todo inject, config, something...
// todo add some tests, although most tests would have to be integration tests...
// todo clear up names, access token/jwt token/refresh token
//export const AUTH_BASE_URL = 'https://authentication.flexinets.se';
const AUTH_BASE_URL = 'http://localhost:65138';     // todo this should be configurable

const STORAGE_KEY = 'react_token';
const LOGIN_URL = `${AUTH_BASE_URL}/token`;
const LOGOUT_URL = `${AUTH_BASE_URL}/logout`;
export const ACCOUNT_URL = `${AUTH_BASE_URL}/api/account/`;



let token = null;
let currentUser = null;
let refreshPromise = null;

axios.defaults.validateStatus = (status) => { return status >= 200 && status < 500; };
axios.interceptors.request.use(async config => authInterceptor(config));


export async function login(username, password) {
    clearTokenContext();

    const response = await axios({
        method: 'post',
        url: LOGIN_URL,
        data: qs.stringify({
            'grant_type': 'password',
            'username': username,
            'password': password
        }),
        config: { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    });
    if (response.status === 200) {
        setJwtToken(response.data);
    }
    return response;
}


/**
 * Begin password reset for email
 * @param {string} email 
 * @param {string} returnUrl Domain part of return url
 */
export async function beginReset(email, returnUrl) {
    const response = await axios({
        method: 'post',
        url: ACCOUNT_URL + '/resetpassword/beginreset/',
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
export async function completeReset(password, passwordConfirm, resetId) {
    return await axios({
        method: 'post',
        url: ACCOUNT_URL + 'resetpassword/completereset/',
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
export async function validateResetToken(resetId) {
    return await axios.get(`${ACCOUNT_URL}resetpassword/validateresettoken/${resetId}`);
}


/**
 * Authinterceptor for axios
 * @param {*} config 
 */
export async function authInterceptor(config) {
    // With credentials must be enabled for requests to login and logout url, because the refresh token is stored as an http only cookie
    if (config.url.indexOf(LOGIN_URL) >= 0 || config.url.indexOf(LOGOUT_URL) >= 0) {
        config.withCredentials = true;
    }
    else {
        const accessToken = await getRefreshedAccessToken();
        if (accessToken !== null) {
            config.headers.authorization = `Bearer ${accessToken}`;
        }
    }
    return config;
}


export async function logout() {
    clearTokenContext();
    await axios.post(LOGOUT_URL);
    console.debug('Logged out');
}


/**
 * Check if a user is logged in.
 * Assumed to be logged in if a token exists, and the refresh token has not expired
 */
export function isLoggedIn() {
    const token = getJwtToken();
    return token !== null && token.refresh_token_expires > new Date().getTime() / 1000;
}


export function getCurrentUser() {
    if (currentUser === null) {
        const token = getJwtToken();
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
export async function getRefreshedAccessToken() {
    const token = getJwtToken();
    if (token !== null) {
        if (isJwtTokenExpired(token.access_token)) {
            console.debug('Token has expired, start refresh maybe');
            const result = await refreshAccessToken();
            console.debug(`token refresh result ${result}`);
        }
        return getJwtToken().access_token;    // test stuff
    }
    return null;
}


/**
 * Check if an email address is available for an admin account
 * @param {any} email 
 */
export async function checkEmailAvailability(email) {
    const response = await axios.get(`${AUTH_BASE_URL}/api/checkemailavailability?email=${email}`);
    return response.data.available;
}



/**
 * Save the token to localStorage
 * @param {string} jwtTokenJson
 */
function setJwtToken(jwtTokenJson) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(jwtTokenJson));
    token = jwtTokenJson;
}


/**
 * Get the token from localStorage or variable if available
 */
function getJwtToken() {
    if (token === null) {
        console.debug('getting token from localstorage');
        token = JSON.parse(localStorage.getItem(STORAGE_KEY));
    }
    return token;
}


/**
 * Refresh access token
 */
async function refreshAccessToken() {
    console.debug('Refreshing access token');

    if (refreshPromise === null) {
        console.debug('No pending access token refresh, starting new');
        refreshPromise = axios({
            method: 'post',
            url: LOGIN_URL,
            data: qs.stringify({ 'grant_type': 'refresh_token' }),
            config: { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
        }).then(response => {
            console.debug('Refreshed access token');
            setJwtToken(response.data);
            return true;
        }).catch(error => {
            console.debug(error);
            if (error.response.data.error === 'invalid_grant') {
                console.debug('Refresh token expired or invalidated');
                clearTokenContext();
                return false;
            }
        }).finally(() => refreshPromise = null);
    }

    return refreshPromise;
}


/**
* Clear the local token context
*/
function clearTokenContext() {
    console.debug('clearing token context');
    localStorage.removeItem(STORAGE_KEY);
    token = null;
    currentUser = null;
}


/**
 * Check if an access token has expired
 * @param {string} jwtToken
 */
function isJwtTokenExpired(jwtToken) {
    const token = decode(jwtToken);
    if (!token.exp) { return null; }

    const expirationDate = new Date(0);
    expirationDate.setUTCSeconds(token.exp);

    return expirationDate < new Date();
}