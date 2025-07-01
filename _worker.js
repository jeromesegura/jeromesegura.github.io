/**
 * DataDome Cloudflare Workers module.
 *
 * @version 1.19.0
 * @author DataDome (https://datadome.co)
 */

/**
 * DataDome default config.
 */

// Server-side key: required to connect to DataDome's protection API.
const DATADOME_LICENSE_KEY = env.DATADOME_LICENSE_KEY;

// Client-side key: optional for automatic JS Tag insertion on HTML pages.
let DATADOME_JS_KEY = 'YOUR_ACTUAL_DATADOME_CLIENT_SIDE_KEY_HERE'; // <--- REPLACE THIS WITH YOUR CLIENT-SIDE KEY

// URL used to download the JS Tag (Change default for 1rst party tag).
let DATADOME_JS_URL = 'https://js.datadome.co/tags.js';

// URL used to send JS data (Used for 1rst party tag).
let DATADOME_JS_ENDPOINT = '';

// Options for power users. Must be null or a string in JSON format.
let DATADOME_JS_TAG_OPTIONS = null;

// API connection timeout in milliseconds (DATADOME_TIMEOUT).
let DATADOME_TIMEOUT = 300;

// Names of header values that will be logged with Logpush.
/** @type Array<string> */
let DATADOME_LOG_VALUES = [];

const HTTP_METHODS_JSTAG = ['GET', 'POST'];

// URIRegex (DATADOME_URI_REGEX) and URIRegexExclusion (DATADOME_URI_REGEX_EXCLUSION)
// are regex used to match URI.
//
// The logic is:
//   Does URI match with URIRegexExclusion if present?
//     if yes stop
//       if no Does URI match with URIRegex if present?
//       if no stop
//       if yes, send to API
//
// Example with a URIRegexExclusion:
//   DATADOME_URI_REGEX_EXCLUSION /\.(js|css|jpg|jpeg|png|ico|gif|tiff|svg|woff|woff2|ttf|eot|mp4|otf)$/
//
// Default behavior excludes static assets.
// To disable a regex, set null value.
let DATADOME_URI_REGEX = null;
let DATADOME_URL_REGEX = null;
let DATADOME_URI_REGEX_EXCLUSION =
    /\.(avi|flv|mka|mkv|mov|mp4|mpeg|mpg|mp3|flac|ogg|ogm|opus|wav|webm|webp|bmp|gif|ico|jpeg|jpg|png|svg|svgz|swf|eot|otf|ttf|woff|woff2|css|less|js|map)$/i;
let DATADOME_HOSTNAME_REGEX_EXCLUSION = null;
let DATADOME_JS_HOSTNAME_REGEX_EXCLUSION = null;
let DATADOME_JS_URI_REGEX_EXCLUSION = null;
let DATADOME_URL_REGEX_EXCLUSION = null;
let DATADOME_JS_URL_REGEX = null;
let DATADOME_JS_URL_REGEX_EXCLUSION = null;
// List of IPs to exclude from DataDome protection. CIDR notation is accepted.
/** @type Array<string> */
let DATADOME_IP_FILTERING = null;
let DATADOME_ENABLE_DEBUGGING = false;
let DATADOME_ENABLE_GRAPHQL_SUPPORT = false;
let DATADOME_ENABLE_REFERRER_RESTORATION = false;
let DATADOME_ENABLE_VOLATILE_SESSION = false;
let DATADOME_MAXIMUM_BODY_SIZE = 25 * 1024; // 25 Kilobytes

/**
 * DataDome constants.
 */

const datadomeContentType = 'application/x-www-form-urlencoded';
const datadomeUserAgent = 'DataDome';
const datadomeURL = new URL('https://api-cloudflare.datadome.co/validate-request/');
const datadomeModuleName = 'CloudflareWorkers';
const datadomeMaxGraphqlBodyLength = 1024;
const datadomeModuleVersion = '1.19.0';
const datadomeIPFilteringIndex = {
    ipv4Ranges: [],
    ipv6Ranges: [],
    ipv4Exact: new Set(),
    ipv6Exact: new Set(),
};

let tagOptions = DATADOME_JS_TAG_OPTIONS;
if (
    (DATADOME_JS_ENDPOINT != null && DATADOME_JS_ENDPOINT !== '') ||
    DATADOME_ENABLE_VOLATILE_SESSION
) {
    let tagOptionsObject = {};
    // Parse the JSON string to create the object...
    if (tagOptions != null && tagOptions !== '') {
        try {
            tagOptionsObject = JSON.parse(tagOptions);
        } catch (e) {
            console.log('Parsing error on DATADOME_JS_TAG_OPTIONS, ' + e);
        }
    }

    if (DATADOME_JS_ENDPOINT) {
        tagOptionsObject.endpoint = DATADOME_JS_ENDPOINT;
    }
    if (DATADOME_ENABLE_VOLATILE_SESSION) {
        tagOptionsObject.volatileSession = true;
    }

    // ... then put it back as a string.
    tagOptions = JSON.stringify(tagOptionsObject);
}
if (DATADOME_IP_FILTERING != null) {
    if (Array.isArray(DATADOME_IP_FILTERING)) {
        initializeIPFilteringIndex();
    } else {
        DATADOME_IP_FILTERING = null;
        console.log('DATADOME_IP_FILTERING must be an Array - IP Filtering is not effective');
    }
}

/**
 * @typedef {function(Request): Promise<Response>} FetchFunction
 */

/**
 * Entry point for the module on fetch events.
 * Activate DataDome protection on Cloudflare pages.
 * @param {FetchFunction} [nextHandler] - Custom handler (on fetch) to call after DataDome.
 * @param {object} [options] - Overrides for DataDome parameters.
 * @returns {void}
 */
function activateDataDome(nextHandler, options = {}) {
    // Override hard-coded parameters.
    const { licenseKey, timeOut } = options;

    // The problematic lines attempting to reassign DATADOME_LICENSE_KEY have been commented out.
    // if (licenseKey != null) {
    //     DATADOME_LICENSE_KEY = licenseKey;
    // }

    if (timeOut != null) {
        DATADOME_TIMEOUT = timeOut;
    }

    // This addEventListener block will be replaced by the export default fetch handler
    // eventListener('fetch', (event) => {
    //     // Fail-safe in case of an unhandled exception
    //     event.passThroughOnException();

    //     if (HTTP_METHODS_JSTAG.includes(event.request.method)) {
    //         const accept = event.request.headers.get('Accept');

    //         // All of the major browsers advertise they are requesting HTML or CSS in the accept header.
    //         // For any browsers that don't (curl, etc), they do not execute JS anyway.
    //         if (accept != null && accept.includes('text/html')) {
    //             /** @type Array<string> */
    //             let mutations = [];

    //             // If no JS key is defined, disable JS tag insertion.
    //             if (DATADOME_JS_KEY !== '' && DATADOME_JS_KEY != null) {
    //                 const url = new URL(event.request.url);

    //                 // Exclude traffic.
    //                 const shoudExcludeFromJSTagInjection =
    //                     (DATADOME_JS_HOSTNAME_REGEX_EXCLUSION != null &&
    //                         DATADOME_JS_HOSTNAME_REGEX_EXCLUSION.test(url.hostname)) ||
    //                     (DATADOME_JS_URI_REGEX_EXCLUSION != null &&
    //                         DATADOME_JS_URI_REGEX_EXCLUSION.test(url.pathname)) ||
    //                     (DATADOME_JS_URL_REGEX_EXCLUSION != null &&
    //                         DATADOME_JS_URL_REGEX_EXCLUSION.test(url.href));

    //                 if (!shoudExcludeFromJSTagInjection) {
    //                     const shouldInjectJSTag =
    //                         DATADOME_JS_URL_REGEX == null ||
    //                         (DATADOME_JS_URL_REGEX != null && DATADOME_JS_URL_REGEX.test(url.href));

    //                     if (shouldInjectJSTag) {
    //                         mutations.push('js-tag');
    //                     }
    //                 }
    //             }

    //             if (DATADOME_ENABLE_VOLATILE_SESSION) {
    //                 mutations.push('volatile-session');
    //             }

    //             if (mutations.length > 0) {
    //                 return event.respondWith(
    //                     validateRequest(
    //                         event.request,
    //                         applyMutationHandler(mutations, nextHandler),
    //                     ),
    //                 );
    //             }
    //         }
    //     }

    //     event.respondWith(validateRequest(event.request, nextHandler));
    // });
}

// The original `if (typeof __webpack_require__ !== 'function') { activateDataDome(); }` is replaced
// by the standard Cloudflare Worker export default fetch handler.

/**
 * Send request to DataDome API Server and process the response.
 * When traffic is allowed, the platform's fetch function will be called.
 * @param {Request} request - Incoming client request.
 * @param {FetchFunction} [fetchHandler] - Override for the default fetch function.
 * @returns {Promise<Response>}
 */
async function validateRequest(request, fetchHandler = globalThis.fetch) {
    try {
        let url = new URL(request.url);
        let newRequest = new Request(url.href, request);
        const volatileClientId = DATADOME_ENABLE_VOLATILE_SESSION ? getVolatileClientId(url) : null;

        if (volatileClientId != null) {
            url.searchParams.delete('ddcid');

            newRequest = new Request(url.href, newRequest);
        }

        if (
            (newRequest.method === 'GET' || newRequest.method === 'HEAD') &&
            DATADOME_URI_REGEX_EXCLUSION != null
        ) {
            if (DATADOME_URI_REGEX_EXCLUSION.test(url.pathname)) {
                return fetchHandler(newRequest);
            }
        }

        if (DATADOME_URI_REGEX != null) {
            if (!DATADOME_URI_REGEX.test(url.pathname)) {
                return fetchHandler(newRequest);
            }
        }

        if (DATADOME_URL_REGEX != null) {
            if (!DATADOME_URL_REGEX.test(url.href)) {
                return fetchHandler(newRequest);
            }
        }

        if (DATADOME_HOSTNAME_REGEX_EXCLUSION != null) {
            if (DATADOME_HOSTNAME_REGEX_EXCLUSION.test(newRequest.headers.get('host'))) {
                return fetchHandler(newRequest);
            }
        }

        if (DATADOME_URL_REGEX_EXCLUSION != null) {
            if (DATADOME_URL_REGEX_EXCLUSION.test(url.href)) {
                return fetchHandler(newRequest);
            }
        }

        if (DATADOME_IP_FILTERING != null) {
            const isIPFiltered = isIPinDataDomeFiltering(getIp(newRequest));
            if (isIPFiltered) {
                return fetchHandler(newRequest);
            }
        }

        const mutatedFields = restoreReferrer(newRequest, url);
        newRequest = mutatedFields.request;
        url = mutatedFields.url;

        const { headers, cf } = newRequest;

        const { clientId, cookiesLength } = getCookieData(newRequest);
        const clientIdHeader = headers.get('x-datadome-clientid');

        const requestData = {
            Key: DATADOME_LICENSE_KEY,
            IP: getIp(newRequest),
            RequestModuleName: datadomeModuleName,
            ModuleVersion: datadomeModuleVersion,
            ClientID: volatileClientId ?? clientIdHeader ?? clientId,
            Accept: headers.get('accept'),
            AcceptCharset: headers.get('accept-charset'),
            AcceptEncoding: headers.get('accept-encoding'),
            AcceptLanguage: headers.get('accept-language'),
            APIConnectionState: 'new',
            AuthorizationLen: getAuthorizationLength(newRequest),
            CacheControl: headers.get('cache-control'),
            Connection: headers.get('connection'),
            ContentType: headers.get('content-type'),
            CookiesLen: cookiesLength,
            From: headers.get('from'),
            HeadersList: getHeaderNames(headers),
            Host: headers.get('host'),
            Method: newRequest.method,
            Origin: headers.get('origin'),
            Port: 0,
            PostParamLen: headers.get('content-length'),
            Pragma: headers.get('pragma'),
            Protocol: headers.get('x-forwarded-proto'),
            Referer: headers.get('referer'),
            Request: url.pathname + url.search,
            SecCHDeviceMemory: headers.get('sec-ch-device-memory'),
            SecCHUA: headers.get('sec-ch-ua'),
            SecCHUAArch: headers.get('sec-ch-ua-arch'),
            SecCHUAFullVersionList: headers.get('sec-ch-ua-full-version-list'),
            SecCHUAModel: headers.get('sec-ch-ua-model'),
            SecCHUAMobile: headers.get('sec-ch-ua-mobile'),
            SecCHUAPlatform: headers.get('sec-ch-ua-platform'),
            SecFetchDest: headers.get('sec-fetch-dest'),
            SecFetchMode: headers.get('sec-fetch-mode'),
            SecFetchSite: headers.get('sec-fetch-site'),
            SecFetchUser: headers.get('sec-fetch-user'),
            ServerHostname: headers.get('host'),
            ServerName: 'cloudflare',
            TimeRequest: getCurrentMicroTime(),
            TlsCipher: cf.tlsCipher,
            TlsProtocol: cf.tlsVersion,
            TrueClientIP: headers.get('true-client-ip'),
            UserAgent: headers.get('user-agent'),
            Via: headers.get('via'),
            'X-Real-IP': headers.get('x-real-ip'),
            'X-Requested-With': headers.get('x-requested-with'),
            XForwardedForIP: headers.get('x-forwarded-for'),
        };

        if (cf != null) {
            requestData['ServerRegion'] = cf.colo;
            if (cf.botManagement != null) {
                requestData['JA3'] = cf.botManagement.ja3Hash;
                requestData['JA4'] = cf.botManagement.ja4;
            }
        }

        // To support pseudo IPv4 feature (with overwrite) for Cloudflare.
        const ipv6Header = headers.get('cf-connecting-ipv6');
        if (ipv6Header != null) {
            requestData['IP'] = ipv6Header;
        }

        if (DATADOME_ENABLE_GRAPHQL_SUPPORT) {
            const graphQLResult = await collectGraphQL(newRequest);
            if (graphQLResult['count'] >