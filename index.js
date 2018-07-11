import decode from 'jwt-decode';
import axios from 'axios';
import qs from 'qs';

// todo this entire module should be wrapped more neatly...
// todo inject, config, something...
//export const LOGIN_URL = 'https://authentication.flexinets.se/token';
//export const LOGOUT_URL = 'https://authentication.flexinets.se/logout';
//const ACCOUNT_URL = 'https://authentication.flexinets.se/api/account/';
//export const AUTH_BASE_URL = 'https://authentication.flexinets.se';
export const LOGIN_URL = 'http://localhost:65138/token';
export const LOGOUT_URL = 'http://localhost:65138/logout';
export const ACCOUNT_URL = 'http://localhost:65138/api/account/';
export const AUTH_BASE_URL = 'http://localhost:65138';
const TOKEN_KEY = 'react_token';


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
        setToken(response.data);
    }
    return response;
}


export async function beginReset(email) {
    const response = await axios({
        method: 'post',
        url: ACCOUNT_URL + 'resetpassword/beginreset/',
        data: {
            EmailAddress: email,
            ReturnUrl: 'https://wifi.flexinets.se/reset/'
        }
    });
    return response;
}


export async function authInterceptor(config) {
    // With credentials must be enabled for requests to login and logout url, because the refresh token is stored as a http only cookie
    if (config.url.indexOf(LOGIN_URL) >= 0 || config.url.indexOf(LOGOUT_URL) >= 0) {
        config.withCredentials = true;
        return config;
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
    const token = getToken();
    return token !== null && token.refresh_token_expires > new Date().getTime() / 1000;
}


export function getCurrentUser() {
    if (currentUser === null) {
        const token = getToken();
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

export async function getRefreshedAccessToken() {
    const token = getToken();
    if (token !== null) {
        if (isTokenExpired(token.access_token)) {
            console.debug('Token has expired, start refresh maybe');
            const result = await refreshToken();
            console.debug(`token refresh result ${result}`);
        }
        return getToken().access_token;    // test stuff
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
 * @param {string} tokenJson
 */
function setToken(tokenJson) {
    localStorage.setItem(TOKEN_KEY, JSON.stringify(tokenJson));
    token = tokenJson;
}


/**
 * Get the token from localStorage or variable if available
 */
function getToken() {
    if (token === null) {
        console.debug('getting token from localstorage');
        token = JSON.parse(localStorage.getItem(TOKEN_KEY));
    }
    return token;
}


/**
 * Refresh access token
 */
async function refreshToken() {
    console.debug('Refreshing access token');

    if (refreshPromise === null) {
        console.debug('No pending access token refresh, starting new');
        refreshPromise = axios({
            method: 'post',
            url: LOGIN_URL,
            data: qs.stringify({ 'grant_type': 'refresh_token' }),
            config: { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
        }).then(response => {
            refreshPromise = null;
            console.debug('Refreshed access token');
            setToken(response.data);
            return true;
        }).catch(error => {
            refreshPromise = null;
            console.debug(error);
            if (error.response.data.error === 'invalid_grant') {
                console.debug('Refresh token expired');
                clearTokenContext();
                return false;
            }
        });
    }

    return refreshPromise;
}


/**
* Clear the local token context
*/
function clearTokenContext() {
    console.debug('clearing token context');
    localStorage.removeItem(TOKEN_KEY);
    token = null;
    currentUser = null;
}


/**
 * Check if an access token has expired
 * @param {string} jwtToken
 */
function isTokenExpired(jwtToken) {
    const token = decode(jwtToken);
    if (!token.exp) { return null; }

    const expirationDate = new Date(0);
    expirationDate.setUTCSeconds(token.exp);

    return expirationDate < new Date();
}