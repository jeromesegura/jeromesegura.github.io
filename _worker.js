/**
 * DataDome Cloudflare Workers module.
 *
 * @version 1.19.0
 * @author DataDome (https://datadome.co)
 */

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

/**
 * @typedef {function(Request): Promise<Response>} FetchFunction
 */

export default {
  async fetch(request, env, ctx) {
    // --- DataDome Configuration Variables (Moved inside fetch) ---

    // Server-side key: required to connect to DataDome's protection API.
    const DATADOME_LICENSE_KEY = env.DATADOME_LICENSE_KEY;

    // Client-side key: optional for automatic JS Tag insertion on HTML pages.
    let DATADOME_JS_KEY = '13BF966546C2220DEC3BC09536AE84'; // <--- REPLACE THIS WITH YOUR CLIENT-SIDE KEY

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

    // --- Tag Options Processing (Moved inside fetch) ---
    let tagOptions = DATADOME_JS_TAG_OPTIONS;
    if (
        (DATADOME_JS_ENDPOINT != null && DATADOME_JS_ENDPOINT !== '') ||
        DATADOME_ENABLE_VOLATILE_SESSION
    ) {
        let tagOptionsObject = {};
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
        tagOptions = JSON.stringify(tagOptionsObject);
    }

    // --- IP Filtering Initialization (Moved inside fetch) ---
    if (DATADOME_IP_FILTERING != null) {
        if (Array.isArray(DATADOME_IP_FILTERING)) {
            initializeIPFilteringIndex();
        } else {
            DATADOME_IP_FILTERING = null;
            console.log('DATADOME_IP_FILTERING must be an Array - IP Filtering is not effective');
        }
    }

    // --- DataDome JS Tag HTML (Moved inside fetch) ---
    const DATADOME_JS_TAG = `
    <script>
        window.ddjskey = "${DATADOME_JS_KEY}";
        window.ddoptions = ${tagOptions ?? '{}'};
        </script>
        <script src="${DATADOME_JS_URL}" async>
    </script>
    `;

    // --- Begin activateDataDome (Modified to be called from fetch) ---
    // Override hard-coded parameters.
    // const { licenseKey, timeOut } = options; // options not directly available here

    // if (licenseKey != null) { // This block was problematic and is removed for good
    //     DATADOME_LICENSE_KEY = licenseKey;
    // }

    // if (timeOut != null) { // This can stay, but DATADOME_TIMEOUT is already defined above
    //     DATADOME_TIMEOUT = timeOut;
    // }
    // --- End activateDataDome section inlined logic ---


    // --- Core Request Validation and Asset Serving ---
    return validateRequest(
      request,
      // The applyMutationHandler ensures JS tag injection and volatile session handling.
      // Its 'nextHandler' argument is now `env.ASSETS.fetch` to serve your static files.
	  (req, opts) => processRequestWithMutations(req, ['js-tag', 'volatile-session'], opts, env.ASSETS.fetch, env)
    );
  }, // End of async fetch(request, env, ctx)
}; // End of export default

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
            if (graphQLResult['count'] > 0) {
                requestData['GraphQLOperationType'] = graphQLResult['type'];
                requestData['GraphQLOperationName'] = graphQLResult['name'];
                requestData['GraphQLOperationCount'] = graphQLResult['count'];
            }
        }

        // Truncate request body values to specific byte length.
        const truncatedData = truncateData(requestData);

        const apiRequest = new Request(datadomeURL, {
            method: 'POST',
            headers: {
                'Content-Type': datadomeContentType,
                'User-Agent': datadomeUserAgent,
            },
            body: stringify(truncatedData),
        });

        if (clientIdHeader) {
            apiRequest.headers.set('X-DataDome-X-Set-Cookie', 'true');
        }

        const fetchApiResponse = DATADOME_ENABLE_VOLATILE_SESSION
            ? processApiRequestWithVolatileSession(apiRequest)
            : fetch(apiRequest);

        const timeoutPromise = new Promise((resolve) => setTimeout(resolve, DATADOME_TIMEOUT));
        const apiResponse = await Promise.race([fetchApiResponse, timeoutPromise]);

        let debugRequest = null;

        if (apiResponse == null) {
            if (DATADOME_ENABLE_DEBUGGING) {
                const logHeaders = new Headers({
                    'X-DataDome-log': 'DD API response is null',
                });
                debugRequest = addHeadersToRequest(newRequest, logHeaders);
                return fetchHandler(debugRequest);
            } else {
                return fetchHandler(newRequest);
            }
        }

        // X-DataDome-cookie is optional and only enabled when allow session is active for the customer.
        if (DATADOME_ENABLE_DEBUGGING && apiResponse.headers.get('X-DataDome-cookie') == null) {
            const logHeaders = new Headers({
                'X-DataDome-log': `X-DataDome-cookie is null, response status is ${apiResponse.status}`,
            });
            debugRequest = addHeadersToRequest(newRequest, logHeaders);
        }

        const ddResponseHeader = apiResponse.headers.get('x-datadomeresponse');

        if (ddResponseHeader != apiResponse.status) {
            const nullOrMismatchLog =
                ddResponseHeader == null
                    ? 'API response does not have a X-DataDomeResponse header'
                    : `X-DataDomeResponse header on API response (${ddResponseHeader}) does not match with status code (${apiResponse.status})`;

            console.log(nullOrMismatchLog);

            if (DATADOME_ENABLE_DEBUGGING) {
                const logHeaders = new Headers({
                    'X-DataDome-log': nullOrMismatchLog,
                });
                debugRequest = addHeadersToRequest(newRequest, logHeaders);
            }
        }

        switch (apiResponse.status) {
            // Redirected or blocked.
            case 403:
            case 401:
            case 302:
            case 301: {
                const blockResponse = buildResponseFromBlock(apiResponse);
                if (DATADOME_LOG_VALUES.length > 0) {
                    logDataDomeHeaders(apiResponse.headers);
                }
                return blockResponse;
            }

            case 200: {
                const enrichedRequest = buildRequestFromAllow(
                    apiResponse,
                    debugRequest != null ? debugRequest : newRequest,
                );
                const response = await fetchHandler(
                    enrichedRequest,
                    DATADOME_ENABLE_VOLATILE_SESSION
                        ? { cid: getCidFromResponse(apiResponse) }
                        : undefined,
                );
                const enrichedResponse = buildResponseFromAllow(apiResponse, response);

                if (DATADOME_LOG_VALUES.length > 0) {
                    logDataDomeHeaders(apiResponse.headers);
                }
                return enrichedResponse;
            }

            default:
                return fetchHandler(newRequest);
        }
    } catch (error) {
        console.log(
            `Error while validating request to ${request.url} (${error.message}) - fetching the resource`,
        );
        return fetchHandler(request);
    }
}

/**
 * Helper functions.
 */

/**
 * Indicates if the Referer header is matching the request URL without the `dd_referrer` query parameter.
 * @param {URL} requestUrl The URL of the incoming request
 * @param {string|null} refererHeaderValue The value of the Referer header
 * @returns {boolean}
 */
function isMatchingRefererHeader(requestUrl, refererHeaderValue) {
    if (refererHeaderValue == null) {
        return false;
    }
    const decodedRefererValue = decodeURIComponent(refererHeaderValue);
    let refererUrl;
    try {
        refererUrl = new URL(decodedRefererValue);
    } catch (e) {
        return false;
    }

    const requestUrlCopy = new URL(requestUrl.href);
    requestUrlCopy.searchParams.delete('dd_referrer');

    return (
        requestUrlCopy.origin === refererUrl.origin &&
        requestUrlCopy.pathname === refererUrl.pathname &&
        requestUrlCopy.search === refererUrl.search
    );
}

/**
 * Defines the fields returned when restorring the referrer.
 * @typedef {Object} RestoredReferrerObjects
 * @property {Request} request
 * @property {URL} url
 */

/**
 * Restores the `Referer` header if:
 * - The `DATADOME_ENABLE_REFERRER_RESTORATION` variable is set to `true`
 * - The `dd_referrer` query parameter is defined
 * - The `Referer` header is matching the request URL without the `dd_referrer` query parameter
 *
 * Once the conditions above are validated:
 * - If the `dd_referrer` value is filled, it will set its URL decoded value in the `Referer` request header.
 * - If the `dd_referrer` value is empty, it will remove the `Referer` request header.
 * - It will remove the `dd_referrer` from the query parameters.
 * @param {Request} request - Incoming client request
 * @param {URL} url - URL of the request
 * @returns {RestoredReferrerObjects} - It returns the mutated field if the referrer has been restored. It returns the original field otherwise.
 */
function restoreReferrer(request, url) {
    if (
        DATADOME_ENABLE_REFERRER_RESTORATION &&
        url.searchParams.has('dd_referrer') &&
        isMatchingRefererHeader(url, request.headers.get('referer'))
    ) {
        const ddReferrer = url.searchParams.get('dd_referrer');
        const newUrl = new URL(url);
        newUrl.searchParams.delete('dd_referrer');
        const newRequest = new Request(newUrl.href, request);
        if (ddReferrer.length) {
            newRequest.headers.set('referer', decodeURIComponent(ddReferrer));
        } else {
            newRequest.headers.delete('referer');
        }

        return { request: newRequest, url: newUrl };
    }

    return { request, url };
}

/**
 * Converts a string into a regular expression.
 * @param {string} str - Input string representing a regular expression.
 * @returns {RegExp}
 */
function strToRegexp(str) {
    if (str == null || str === '') {
        return null;
    }

    try {
        const delimiter = str[0];
        const flags = str.replace(
            new RegExp('^' + delimiter + '.*' + delimiter + '([dgimsuy]*)$'),
            '$1',
        );
        const pattern = str.replace(
            new RegExp('^' + delimiter + '(.*?)' + delimiter + flags + '$'),
            '$1',
        );

        return new RegExp(pattern, flags);
    } catch (_) {
        // If regexp parsing failed.
    }

    return null;
}

/**
 * Converts an object into a URL-encoded string.
 * @param {object} input - Object with request data.
 * @returns {string}
 */
function stringify(input) {
    return input ? new URLSearchParams(input).toString() : '';
}

/**
 * Returns the current timestamp in microseconds.
 * @returns {number}
 */
function getCurrentMicroTime() {
    return Date.now() * 1000;
}

/**
 * Returns a comma-separated list of all request headers.
 * @param {Headers} headers - Request headers.
 * @returns {string}
 */
function getHeaderNames(headers) {
    return Array.from(headers.keys()).join(',');
}

/**
 * Returns the length of the `Authorization` request header.
 * @param {Request} request - Incoming client request.
 * @returns {number}
 */
function getAuthorizationLength(request) {
    const authorization = request.headers.get('authorization');
    return authorization == null ? 0 : authorization.length;
}

/**
 * Returns the `ddcid` query parameter from a given URL.
 * @param {URL} url - URL to search.
 * @returns {string?}
 */
function getVolatileClientId(url) {
    const ddcid = url.searchParams.get('ddcid');

    if (ddcid != null) {
        try {
            return decodeURIComponent(ddcid);
        } catch {
            return ddcid;
        }
    }

    return null;
}

/**
 * Returns a simple object with two properties:
 * - The client ID from the `datadome` cookie.
 * - The total length of the `Cookie` request header.
 * @param {Request} request - Incoming client request.
 * @returns {{ clientId: string, cookiesLength: number }}
 */
function getCookieData(request) {
    const cookies = request.headers.get('cookie');

    let clientId = '';
    let cookiesLength = 0;

    if (cookies != null) {
        const cookieMap = parseCookieString(cookies);

        clientId = cookieMap.get('datadome');
        cookiesLength = cookies.length;
    }

    return { clientId, cookiesLength };
}

/**
 * Transform a cookie string into dictionary form.
 * @param {string} input - Cookies in string form, typically coming from a `Cookie` HTTP header.
 * @returns {Map<string, string>}
 */
function parseCookieString(input) {
    let cookies = new Map();

    input.split(/; */).forEach((pair) => {
        let eqIndex = pair.indexOf('=');

        if (eqIndex > 0) {
            const key = pair.substring(0, eqIndex).trim();
            let value = pair.substring(++eqIndex, eqIndex + pair.length).trim();

            if (value[0] === '"') {
                value = value.slice(1, -1);
            }

            if (!cookies.has(key)) {
                cookies.set(key, tryDecode(value));
            }
        }
    });

    return cookies;
}

/**
 * Safely decode a string that might be URL-encoded.
 * @param {string} input
 * @returns {string}
 */
function tryDecode(input) {
    try {
        return decodeURIComponent(input);
    } catch (e) {
        return input;
    }
}

/**
 * Logs headers for Logpush through console.log().
 * @param {Headers} sourceHeaders - Source headers for the values to log.
 * @returns {void}
 */
function logDataDomeHeaders(sourceHeaders) {
    const logValuesIndex = DATADOME_LOG_VALUES.map((name) => {
        const logValue = sourceHeaders.get(name.trim());
        return logValue != null ? logValue : '-';
    });
    const logLine = logValuesIndex.join(';');

    // Log to Logpush.
    console.log(logLine);
}

/**
 * Merge enriched headers from an API response with another `Headers` object.
 * @param {Headers} apiResponseHeaders - Headers from an API response.
 * @param {Headers} targetHeaders - Headers to merge with the enriched headers sent by the API.
 * @param {string} sourceName - Name of the header that lists headers to merge.
 * @returns {Headers}
 */
function mergeHeaders(apiResponseHeaders, targetHeaders, sourceName) {
    const datadomeHeadersStr = apiResponseHeaders.get(sourceName);
    if (datadomeHeadersStr == null) {
        return targetHeaders;
    }

    const modifiedHeaders = new Headers(targetHeaders);

    datadomeHeadersStr.split(' ').forEach((datadomeHeaderName) => {
        const datadomeHeaderValue = apiResponseHeaders.get(datadomeHeaderName);

        if (datadomeHeaderValue != null) {
            const allowSessionCookie = cookieFromAllowSession(modifiedHeaders);
            // Docs for Headers: https://developers.cloudflare.com/workers/platform/headers/
            if (datadomeHeaderName == 'Set-Cookie') {
                // Based on RFC 7230 Section 3.2.2 'Set-Cookie' may appear multiple times in a response.
                if (allowSessionCookie != null) {
                    modifiedHeaders.append(datadomeHeaderName, allowSessionCookie);
                    modifiedHeaders.delete('X-DataDome-Cookie');
                } else {
                    modifiedHeaders.append(datadomeHeaderName, datadomeHeaderValue);
                }
            } else if (datadomeHeaderName == 'X-Set-Cookie') {
                if (allowSessionCookie != null) {
                    modifiedHeaders.set(datadomeHeaderName, allowSessionCookie);
                    modifiedHeaders.delete('X-DataDome-Cookie');
                } else {
                    modifiedHeaders.set(datadomeHeaderName, datadomeHeaderValue);
                }
            } else {
                modifiedHeaders.set(datadomeHeaderName, datadomeHeaderValue);
            }
        }
    });

    return modifiedHeaders;
}

/**
 * Creates a request for the origin with enriched headers from the API response.
 * @param {Response} apiResponse - API response resulting with an allow.
 * @param {Request} originalRequest - Original client request.
 * @returns {Request}
 */
function buildRequestFromAllow(apiResponse, originalRequest) {
    return new Request(originalRequest, {
        headers: mergeHeaders(
            apiResponse.headers,
            originalRequest.headers,
            'X-DataDome-Request-Headers',
        ),
    });
}

/**
 * Creates an allow response with enriched headers from the API response.
 * @param {Response} apiResponse - API response resulting with an allow.
 * @param {Response} response - Response from the origin.
 * @returns {Response}
 */
function buildResponseFromAllow(apiResponse, response) {
    return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: mergeHeaders(apiResponse.headers, response.headers, 'X-DataDome-Headers'),
    });
}

/**
 * Creates a block response with enriched headers from the API response.
 * @param {Response} apiResponse - API response resulting with a block.
 * @returns {Response}
 */
function buildResponseFromBlock(apiResponse) {
    return new Response(apiResponse.body, {
        status: apiResponse.status,
        statusText: apiResponse.statusText,
        headers: mergeHeaders(apiResponse.headers, new Headers(), 'X-DataDome-Headers'),
    });
}

/**
 * Returns the allowed cookie if the origin uses Allow Session.
 * @param {Headers} originHeaders - Headers from the origin.
 * @returns {string?}
 */
function cookieFromAllowSession(originHeaders) {
    return originHeaders.get('X-DataDome-cookie');
}

/**
 * Returns a copy of the original request with new headers.
 * @param {Request} request - Incoming client request.
 * @param {Headers} headers - Headers to add to the request.
 * @returns {Request}
 */
function addHeadersToRequest(request, headers) {
    const logHeaders = new Headers(request.headers);
    for (const [name, value] of headers.entries()) {
        logHeaders.set(name, value);
    }

    return new Request(request, {
        headers: logHeaders,
    });
}

/**
 * Returns the same object with values truncated according to internal rules.
 * @param {object} requestData - Raw data from incoming request.
 * @returns {object}
 */
function truncateData(requestData) {
    try {
        for (let [name, value] of Object.entries(requestData)) {
            switch (name) {
                // 8 bytes
                case 'SecCHDeviceMemory':
                case 'SecCHUAMobile':
                case 'SecFetchUser':
                    requestData[name] = truncateValue(value, 8);
                    break;
                // 16 bytes
                case 'SecCHUAArch':
                    requestData[name] = truncateValue(value, 16);
                    break;
                // 32 bytes
                case 'SecCHUAPlatform':
                case 'SecFetchDest':
                case 'SecFetchMode':
                    requestData[name] = truncateValue(value, 32);
                    break;
                // 64 bytes
                case 'ContentType':
                case 'JA4':
                case 'SecFetchSite':
                    requestData[name] = truncateValue(value, 64);
                    break;
                // 128 bytes
                case 'AcceptCharset':
                case 'AcceptEncoding':
                case 'CacheControl':
                case 'ClientID':
                case 'Connection':
                case 'From':
                case 'GraphQLOperationName':
                case 'Pragma':
                case 'SecCHUA':
                case 'SecCHUAModel':
                case 'TrueClientIP':
                case 'X-Real-IP':
                case 'X-Requested-With':
                    requestData[name] = truncateValue(value, 128);
                    break;
                // 256 bytes
                case 'AcceptLanguage':
                case 'SecCHUAFullVersionList':
                case 'Via':
                    requestData[name] = truncateValue(value, 256);
                    break;
                // 512 bytes
                case 'Accept':
                case 'HeadersList':
                case 'Host':
                case 'Origin':
                case 'ServerHostname':
                case 'ServerName':
                    requestData[name] = truncateValue(value, 512);
                    break;
                // 512 bytes backwards
                case 'XForwardedForIP':
                    requestData[name] = truncateValue(value, -512);
                    break;
                // 768 bytes
                case 'UserAgent':
                    requestData[name] = truncateValue(value, 768);
                    break;
                // 1024 bytes
                case 'Referer':
                    requestData[name] = truncateValue(value, 1024);
                    break;
                // 2048 bytes
                case 'Request':
                    requestData[name] = truncateValue(value, 2048);
                    break;
                default:
                    break;
            }
        }
    } catch (e) {
        console.error(e);
        console.error(e.message);
    }

    return requestData;
}

/**
 * Returns the same value, truncated according to a ceiling limit.
 * @param {string} value
 * @param {number} size
 * @returns {string}
 */
function truncateValue(value, size) {
    if (!value) {
        return '';
    }
    return size >= 0 ? value.slice(0, size) : value.slice(size);
}

/**
 *
 * @param {Request} request
 * @returns {boolean} true if it matches graphql signature
 */
function isGraphQLRequest(request) {
    const contentType = request.headers.get('content-type');
    if (request.method == 'POST' && request.body != null && contentType === 'application/json') {
        const url = new URL(request.url);
        return url.pathname.toLowerCase().indexOf('graphql') > -1;
        // Uncomment the following lines to allow graphql extraction
        // from query searchParams
        // } else if(request.method = 'GET') {
        //     const url = new URL(request.url);
        //     return url.searchParams.get('query');
    }
    return false;
}

/**
 * The data contained in the request body
 * @class GraphQLData
 */
class GraphQLData {
    constructor() {
        this.type = 'query';
        this.name = '';
        this.count = 0;
    }
}

/**
 * This function read the body and extract it chunk-by-chunk until the query is found.
 * @param {Request} request
 * @returns {Promise<string | null>} the stringified body with the query field (or null if not found)
 */
async function extractGraphQLQueryFromBody(request) {
    const regex = /"query"\s*:\s*(".*)/;
    const textDecoder = new TextDecoder();
    const reader = request.body.getReader({ mode: 'byob' });
    let iteration = 0;
    let bodyString = '';
    let match = [];

    while (true) {
        if (iteration * datadomeMaxGraphqlBodyLength >= DATADOME_MAXIMUM_BODY_SIZE) {
            break;
        }

        const buffer = new Uint8Array(datadomeMaxGraphqlBodyLength); // Create a buffer with a specific size
        const { value, done } = await reader.readAtLeast(buffer.length, buffer);

        if (value === undefined && done === true) {
            break;
        }

        const chunk = textDecoder.decode(value, { stream: !done });
        bodyString += chunk;

        // We only keep the 2 last chunks to do not perform the regex matching on a large string
        if (bodyString.length > 2 * datadomeMaxGraphqlBodyLength) {
            bodyString = bodyString.slice(-2 * datadomeMaxGraphqlBodyLength);
        }

        match = bodyString.match(regex);
        if (match !== null && match.length > 0) {
            return match[1];
        }

        if (done === true) {
            break;
        }
        iteration += 1;
    }

    return null;
}

/**
 * This function returns the GraphQL Query from the query params
 * @param {Request} request
 * @returns {string|null} The GraphQL query to be parsed (or null if not found)
 */
function extractGraphQLQueryFromQueryParams(request) {
    const url = new URL(request.url);
    return url.searchParams.get('query');
}

/**
 * This function read the GraphQL query and extract its GraphQLData information.
 * @param {string} queryString The GraphQL query to be parsed
 * @returns {GraphQLData}
 */
function parseGraphQLQuery(queryString) {
    const result = new GraphQLData();
    const regex =
        /(?<operationType>query|mutation|subscription)\s*(?<operationName>[A-Za-z_][A-Za-z0-9_]*)?\s*[\({@]/gm;

    const matches = Array.from(queryString.matchAll(regex));
    let matchLength = matches.length;
    if (matchLength > 0) {
        result['type'] = matches[0].groups.operationType ?? 'query';
        result['name'] = matches[0].groups.operationName ?? '';
    } else {
        const shorthandSyntaxRegex =
            /"(?<operationType>(?:query|mutation|subscription))?\s*(?<operationName>[A-Za-z_][A-Za-z0-9_]*)?\s*[({@]/gm;
        const shorthandSyntaxMatches = Array.from(queryString.matchAll(shorthandSyntaxRegex));
        matchLength = shorthandSyntaxMatches.length;
    }
    result['count'] = matchLength;

    return result;
}

/**
 * Tries to extract the graphQL operationName, operationType and count from the request
 *
 * Does nothing if the request is not a graphQL request
 *
 * @param {Request} request
 * @returns {Promise<GraphQLData>}
 */
async function collectGraphQL(request) {
    if (!isGraphQLRequest(request)) {
        return new GraphQLData();
    }

    let queryString = extractGraphQLQueryFromQueryParams(request);
    if (queryString !== null) {
        return parseGraphQLQuery(queryString);
    }
    const clonedRequest = await request.clone(); // Need to clone to avoid consuming the body (streamable can be read only once)
    queryString = await extractGraphQLQueryFromBody(clonedRequest);
    if (queryString !== null) {
        return parseGraphQLQuery(queryString);
    }
    return new GraphQLData();
}

// JS code to integrate DataDome's JS Tag in HTML pages.
// Moved inside fetch, so it will be defined there.
// const DATADOME_JS_TAG = `
// <script>
//     window.ddjskey = "${DATADOME_JS_KEY}";
//     window.ddoptions = ${tagOptions ?? '{}'};
//     </script>
//     <script src="${DATADOME_JS_URL}" async>
// </script>
// `;

/**
 * Element handler for HTMLRewriter.
 * Inserts a JS Tag snippet in the page.
 * Docs: https://developers.cloudflare.com/workers/runtime-apis/html-rewriter/#handlers
 */
class TagLoaderInserter {
    constructor() {
        this.isSet = false;
    }

    element(element) {
        if (!this.isSet) {
            this.isSet = true;
            element.prepend(DATADOME_JS_TAG, {
                html: true,
            });
        }
    }
}

/**
 * Element handler for HTMLRewriter.
 * Adds a `ddcid` on the page's global context with the last value of the `datadome` cookie.
 */
class VolatileSessionRewriter {
    /**
     * @param {string} cid - Value of the `datadome` cookie.
     */
    constructor(cid) {
        this.cid = cid;
    }

    element(element) {
        if (element.tagName === 'body') {
            const script = `<script>window.ddcid = "${this.cid}";</script>`;
            element.prepend(script, { html: true });
        }
    }
}

/**
 * Fetch handler to insert the JS Tag dynamically.
 * @param {Array<string>} mutations - List of mutations to apply.
 * @param {FetchFunction} [nextHandler] - Custom handler (on fetch) to call after the JS Tag insertion.
 * @returns {FetchFunction}
 */
function applyMutationHandler(mutations, nextHandler, env) { // Added 'env'
    return function (request, options = {}) {
        return processRequestWithMutations(request, mutations, options, nextHandler, env); // Pass 'env'
    };
}

/**
 * Handle all non-proxied requests. Send HTML on for further processing
 * and pass everything else through unmodified.
 * @param {Request} enrichedRequest - Incoming client request with enriched headers from DataDome.
 * @param {Array<string>} mutations - List of mutations to apply.
 * @param {object} options - Options to take into account when processing mutations.
 * @param {FetchFunction} [fetchHandler] - Handler to fetch the request; the platform's fetch will be used by default.
 */
async function processRequestWithMutations(
    enrichedRequest,
    mutations,
    options,
    fetchHandler, // No default here, we'll always pass env.ASSETS.fetch
    env // Added 'env' here
) {
    const response = await (fetchHandler || env.ASSETS.fetch)(enrichedRequest); // Use fetchHandler if provided, else env.ASSETS.fetch
    // We will insert the tag in *all* HTTP responses with HTML content type.
    if (response.ok) {
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('text/html')) {
            let rewriter = new HTMLRewriter();

            mutations.forEach((mutation) => {
                switch (mutation) {
                    case 'js-tag': {
                        const tagLoaderInserter = new TagLoaderInserter();
                        rewriter = rewriter
                            .on('head', tagLoaderInserter)
                            .on('body', tagLoaderInserter);
                        break;
                    }
                    case 'volatile-session': {
                        const { cid } = options;

                        if (cid != null) {
                            const mutator = new VolatileSessionRewriter(cid, enrichedRequest.url);
                            rewriter = rewriter.on('body', mutator);
                        }
                        break;
                    }
                }
            });

            return rewriter.transform(response);
        }
    }

    return response;
}

/**
 * Injects the volatile session value on block responses in HTML.
 * @param {Request} apiRequest - Validation request to send to DataDome's API.
 * @returns {Promise<Response>}
 */
async function processApiRequestWithVolatileSession(apiRequest) {
    const apiResponse = await fetch(apiRequest);

    if (apiResponse.status === 403 || apiResponse.status === 401) {
        const contentType = apiResponse.headers.get('content-type');
        if (contentType && contentType.includes('text/html')) {
            const cid = getCidFromResponse(apiResponse);

            if (cid != null) {
                const mutator = new VolatileSessionRewriter(cid);
                const rewriter = new HTMLRewriter();

                return rewriter.on('body', mutator).transform(apiResponse);
            }
        }
    }

    return apiResponse;
}

/**
 * Returns `true` if the input is an array of string values.
 * @param {any} input - Input to validate.
 * @returns {boolean}
 */
function isArrayOfString(input) {
    return Array.isArray(input) ? input.every((value) => typeof value === 'string') : false;
}

/**
 * Get the client's IP address from the `CF-Connecting-IP` header.
 * Docs: https://developers.cloudflare.com/fundamentals/get-started/reference/http-request-headers/#cf-connecting-ip
 * @param {Request} request - Incoming client request.
 * @returns {string?}
 */
function getIp(request) {
    return request.headers.get('cf-connecting-ip');
}

/**
 * Get the value of the `datadome` cookie from a given response.
 * @param {Response} response - HTTP response.
 * @returns {string?}
 */
function getCidFromResponse(response) {
    const cookieStart = 'datadome=';
    const cookies = response.headers.getAll('Set-Cookie');

    for (let i = 0; i < cookies.length; ++i) {
        const cookie = cookies[i];
        if (cookie.startsWith(cookieStart)) {
            const endIndex = cookie.indexOf(';');
            if (endIndex > -1) {
                return cookie.slice(cookieStart.length, endIndex);
            }
        }
    }

    return null;
}

/**
 * Checks if a string is a valid IPv4 address.
 * @param {string} ip - The IP to check.
 * @returns {boolean} - True if the IP is a valid IPv4 address.
 */
function isIPv4(ip) {
    // four decimal numbers separated by dots
    const ipv4Pattern = /^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$/;
    return ipv4Pattern.test(ip);
}

/**
 * Checks if a string is a valid IPv6 address.
 * @param {string} ip - The IP to check.
 * @returns {boolean} - True if the IP address is IPv6.
 */
function isIPv6(ip) {
    // eight groups of four hexadecimal digits separated by colons
    // '::' can be used for groups of zeros
    const ipv6Pattern =
        /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(([0-9a-fA-F]{1,4}:){1,7}:)|(([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})|(([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2})|(([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3})|(([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4})|(([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5})|([0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6}))|(::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})|(::))$/;
    return ipv6Pattern.test(ip);
}
/**
 * Converts an IPv4 address to a 32-bit integer.
 * @param {string} ip - The IPv4 address in dotted decimal notation like '192.168.1.1'.
 * @returns {number} - The integer representation of the IPv4.
 */
function ipv4ToInt(ip) {
    return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0);
}

/**
 * Converts an IPv6 address to a hexadecimal string.
 * @param {string} ipv6 - The IPv6 address in string notation like '2001:db8::'.
 * @returns {string} - The hexadecimal representation of the IPv6.
 */
function ipv6ToHex(ipv6) {
    const expanded = ipv6
        .split('::')
        .reduce((acc, part, idx, arr) => {
            if (idx === 0) {
                acc.push(part.split(':'));
            } else {
                // fill in '::' with zeros
                const missing = 8 - (arr[0].split(':').length + (arr[1]?.split(':').length || 0));
                acc.push(Array(missing).fill('0')); // Corrected line
            }
            return acc;
        }, [])
        .flat();

    return expanded.map((block) => block.padStart(4, '0')).join('');
}

/**
 * Generates a hexadecimal mask for a given prefix length.
 * @param {number} prefixLength - The CIDR prefix length.
 * @returns {string} - The hexadecimal mask.
 */
function generateMaskHex(prefixLength) {
    // number of digits set to F (all bits are 1)
    const fullHexDigits = Math.floor(prefixLength / 4);
    // number of remaining bits
    const partialBits = prefixLength % 4;

    const mask = 'F'.repeat(fullHexDigits);
    if (partialBits > 0) {
        const partialHex = parseInt('1'.repeat(partialBits).padEnd(4, '0'), 2)
            .toString(16)
            .toUpperCase();
        return (mask + partialHex).padEnd(32, '0');
    }

    return mask.padEnd(32, '0');
}

/**
 * Applies a hexadecimal mask to an IPv6 hexadecimal string.
 * @param {string} ip - The IPv6 address in hexadecimal.
 * @param {string} mask - The CIDR mask in hexadecimal.
 * @returns {string} - The masked IPv6 address in hexadecimal.
 */
function applyMaskHexa(ip, mask) {
    let result = '';
    for (let i = 0; i < ip.length; i++) {
        const maskedDigit = parseInt(ip[i], 16) & parseInt(mask[i], 16);
        result += maskedDigit.toString(16).toUpperCase();
    }
    return result;
}

/**
 * Checks if an IPv4 address is is a given CIDR range.
 * @param {string} ip - The IPv4 address to check.
 * @param {string} cidr - The CIDR range, eg '192.168.1.0/24'.
 * @returns {boolean} - True if the IPv4 is in the range.
 */
function isIPv4InCIDR(ip, cidr) {
    const [range, prefixLength] = cidr.split('/');
    // left-shifting 1 by (32 - prefixLength), subtracting 1 to get the corresponding bitmask, and inverting the bits to form the mask
    const mask = ~((1 << (32 - prefixLength)) - 1);

    const ipInt = ipv4ToInt(ip); // Convert IP to integer
    const rangeInt = ipv4ToInt(range); // Convert CIDR base range to integer

    // Check if the IP matches the CIDR range using the mask
    return (ipInt & mask) === (rangeInt & mask);
}

/**
 * Sorts an array of CIDR ranges by their prefix lengths in ascending order
 * so that wider ranges come first.
 *
 * @param {string} a - CIDR range, eg '2001:db8::/32'.
 * @param {string} b - CIDR range, eg '192.168.1.0/24'.
 * @returns {number}
 */
function sortRanges(a, b) {
    const prefixA = parseInt(a.split('/')[1], 10);
    const prefixB = parseInt(b.split('/')[1], 10);
    return prefixA - prefixB;
}

/**
 * Checks if an IPv6 address is in a given CIDR range.
 * @param {string} ip - The IPv6 address to check.
 * @param {string} cidr - The CIDR range, eg '2001:db8::/32'.
 * @returns {boolean} - True if the IPv6 is in the range.
 */
function isIPv6InCIDR(ip, cidr) {
    const [range, prefixLength] = cidr.split('/');
    const maskLength = parseInt(prefixLength, 10);

    // Convert the IPv6 address and range to hexadecimal strings
    const ipHex = ipv6ToHex(ip);
    const rangeHex = ipv6ToHex(range);

    // Generate the CIDR mask as a hexadecimal string
    const maskHex = generateMaskHex(maskLength);

    // Check if the masked IP matches the masked range
    return applyMaskHexa(ipHex, maskHex) === applyMaskHexa(rangeHex, maskHex);
}

/**
 * Initializes an index based on DATADOME_IP_FILTERING to group IPs and ranges
 * to optimize the structure and make it faster to query
 */
function initializeIPFilteringIndex() {
    for (const entry of DATADome_IP_FILTERING) {
        if (entry.includes('/')) {
            const [range] = entry.split('/');
            if (isIPv4(range)) {
                datadomeIPFilteringIndex.ipv4Ranges.push(entry);
            } else if (isIPv6(range)) {
                datadomeIPFilteringIndex.ipv6Ranges.push(entry);
            }
        } else {
            if (isIPv4(entry)) {
                datadomeIPFilteringIndex.ipv4Exact.add(entry);
            } else if (isIPv6(entry)) {
                datadomeIPFilteringIndex.ipv6Exact.add(entry);
            }
        }
    }

    // Sort CIDR ranges by prefix length so larger ranges come first
    datadomeIPFilteringIndex.ipv4Ranges.sort(sortRanges);

    datadomeIPFilteringIndex.ipv6Ranges.sort(sortRanges);
}

/**
 * Determines if a given IP is in DATADOME_IP_FILTERING CIDR ranges.
 * @param {string} ip - The IP address to check (IPv4 or IPv6).
 * @returns {boolean} - True if the IP is in any of the CIDR ranges, otherwise false.
 */
function isIPinDataDomeFiltering(ip) {
    if (isIPv4(ip)) {
        // Exact matches
        if (datadomeIPFilteringIndex.ipv4Exact.has(ip)) {
            return true;
        }
        // CIDR
        for (const cidr of datadomeIPFilteringIndex.ipv4Ranges) {
            if (isIPv4InCIDR(ip, cidr)) {
                return true;
            }
        }
    }
    if (isIPv6(ip)) {
        // Exact matches
        if (datadomeIPFilteringIndex.ipv6Exact.has(ip)) {
            return true;
        }
        // CIDR
        for (const cidr of datadomeIPFilteringIndex.ipv6Ranges) {
            if (isIPv6InCIDR(ip, cidr)) {
                return true;
            }
        }
    }

    return false;
}