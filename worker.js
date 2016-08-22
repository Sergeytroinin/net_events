'use strict';
const fs = require('fs'),
    zlib = require('zlib'),
    pcap = require('pcap'),
    maxmind = require('maxmind'),
    cookie = require('cookie'),
    DNS = require("pcap/decode/dns"),

    events = require('./events'),
    HTTPSession = require("./session");

var lookup;


const POP_PORTS = [110,995];
const SMTP_PORTS = [25,587,465];
const IMAP_PORTS = [143,993];

const ENCRYPTED_PORTS = [995, 587, 465, 993];

const MAIL_PORTS = POP_PORTS
    .concat(SMTP_PORTS)
    .concat(IMAP_PORTS);


const mailSessionData = {};


/**
 * Waiting for interface name and start observing
 */
process.on('message', (e) => {

    if (e.name === 'setInterface') {
        startObserve(e.data)
    }

});


/**
 * To keep format consistent we use guid both for HTTP and DNS events
 * DNS has it's own id and we use it like keys for keeping guid for each request/response pair
 * @type {{}}
 */
const DNS_IDS = {};


/**
 * Send event to main process
 * @param eventData
 */
function sendEvent(eventData) {

    let name = eventData.eventName;

    delete eventData.eventName;

    process.send({
        eventName: name,
        data: eventData
    })

}


/**
 * Check if request/response gzipped
 * @param headers
 * @returns {boolean}
 */
function isGzipped(headers) {

    let encoding = headers['Content-Encoding'] || headers['Accept-Encoding'];

    return !!(encoding && /gzip/.test(encoding));

}


/**
 * Return GUID
 * @returns {string}
 */
function guid() {
    function s4() {
        return Math.floor((1 + Math.random()) * 0x10000)
            .toString(16)
            .substring(1);
    }

    return s4() + s4() + '-' + s4() + '-' + s4() + '-' +
        s4() + '-' + s4() + s4() + s4();
}


function sendError() {

}


/**
 * Handler for tcp session object
 * @param tcpSession
 */
function onTCPSession(tcpSession) {

    const httpSession = new HTTPSession(tcpSession);

    // TODO Need a better way
    let ip = tcpSession.dst.split(':')[0];

    let id = guid();
    let country = getCountryByIP(ip);

    // TODO Need to find more common way to create this objects
    let responseObject = {
        id: id,
        src: tcpSession.src_name,
        dst: tcpSession.dst_name,
        country: country
    };

    let requestObject = {
        id: id,
        src: tcpSession.src_name,
        dst: tcpSession.dst_name,
        country: country
    };

    let responseBuffer = new Buffer('');
    let requestBuffer = new Buffer('');

    /**
     * Handle http session errors
     */
    httpSession.on("http error", function () {

        let message = "Error in HTTPSession module";

        sendError(message)
    });

    /**
     * Handle http request start
     * TODO Need to find more common way to fill this data
     */
    httpSession.on("http request", function (session) {

        let req = session.request;

        let id = guid();

        requestObject.id = id;
        responseObject.id = id;

        requestObject.headers = req.headers;

        if (requestObject.headers['Cookie']) {
            requestObject.headers['Cookie'] = cookie.parse(requestObject.headers['Cookie'])
        }

        requestObject.url = req.url;
        requestObject.method = req.method;
        requestObject.host = req.headers['Host'] || req.headers['Server'];

    });

    /**
     * Handle request body
     * Each packet added to common buffer
     */
    httpSession.on("http request body", function (session, data) {
        requestBuffer = Buffer.concat([requestBuffer, data]);
    });

    /**
     * Handle complete request
     */
    httpSession.on("http request complete", function () {

            let parseBody;


            if (isGzipped(requestObject.headers)) {
                try {
                    parseBody = zlib.unzipSync(requestBuffer).toString('utf8', 0, requestBuffer.length);
                } catch (e) {
                    parseBody = requestBuffer.toString('utf8', 0, requestBuffer.length);
                }

            } else {
                parseBody = requestBuffer.toString('utf8', 0, requestBuffer.length);
            }

            try {
                parseBody = JSON.parse(requestObject.parseBody)
            } catch (e) {
            }


            if (requestBuffer.length) {
                requestObject.buffer = requestBuffer;
            }

            requestObject.parseBody = parseBody;

            requestBuffer = new Buffer('');

            requestObject.eventName = events.HTTP_REQUEST_EVENT

            sendEvent(requestObject)

        }
    );


    httpSession.on("http response", function (session) {
        let req = session.response;

        responseObject.headers = req.headers;

        if (responseObject.headers['Cookie']) {
            responseObject.headers['Cookie'] = cookie.parse(responseObject.headers['Cookie'])
        }

        responseObject.url = requestObject.url;
        responseObject.status = req.status_code;

    });

    httpSession.on("http response body", function (session, data) {
        responseBuffer = Buffer.concat([responseBuffer, data]);
    });

    httpSession.on("http response complete", function () {
        if (responseBuffer.length) {

            responseObject.buffer = responseBuffer;

            if (isGzipped(responseObject.headers)) {
                try {
                    responseObject.parseBody = zlib.unzipSync(responseBuffer).toString('utf8', 0, responseBuffer.length);
                } catch (e) {
                    responseObject.parseBody = responseBuffer.toString('utf8', 0, responseBuffer.length);
                }
            } else {
                responseObject.parseBody = responseBuffer.toString('utf8', 0, responseObject.length);
            }

            try {
                requestObject.parseBody = JSON.parse(requestObject.parseBody)
            } catch (e) {
            }

        }

        responseBuffer = new Buffer('');

        responseObject.eventName = events.HTTP_RESPONSE_EVENT;

        sendEvent(responseObject)

    });

}


/**
 * Run observer
 * @param interfaceName
 */
function startObserve(interfaceName) {

    const tcpTracker = new pcap.TCPTracker(),
        pcapSession = pcap.createSession(interfaceName, "");

    lookup = maxmind.open(__dirname + '/GeoLite2-Country.mmdb', {
        cache: {
            max: 1000,
            maxAge: 1000 * 60 * 60
        }
    });

    tcpTracker.on('session', function (session) {

        onTCPSession(session);

        sendEvent({
            eventName: events.CONNECT_EVENT,
            src: session.src,
            dst: session.dst
        });

        session.on('end', function (session) {

            completeMailSession(session);

            sendEvent({
                eventName: events.DISCONNECT_EVENT,
                src: session.src,
                dst: session.dst
            });

        });

    });

    pcapSession.on('packet', function (rawPacket) {
        let packet = pcap.decode.packet(rawPacket);

        parsePacket(packet, sendEvent);

        tcpTracker.track_packet(packet);
    });

}


/**
 * Get country by provided ip using maxmind
 * TODO Implement locale handler
 * @param ip
 * @returns {*}
 */
function getCountryByIP(ip) {

    let geoData = lookup.get(ip);

    //noinspection JSUnresolvedVariable
    if (geoData && geoData.country && geoData.country.names) {
        //noinspection JSUnresolvedVariable
        return geoData.country.names.en;
    } else {
        return 'Unrecognized';
    }

}


/**
 * Wrapper for getCountryByIP processed rawPacket
 * @param rawPacket
 * @returns {*}
 */
function getCountry(rawPacket) {

    let ip = rawPacket.payload.payload.saddr.toString();

    return getCountryByIP(ip);

}


/**
 * Process rawPacket and return object, which contain domains as a keys
 * and lists of connected ip-addresses as a values
 * @param rawPacket
 * @returns {{}}
 */
function parseDNS(rawPacket) {

    let data = {};
    let ip = rawPacket.payload.payload;
    let tcp = ip.payload;

    const dns = new DNS().decode(tcp.data, 0, tcp.data.length);

    let src = ip.saddr.toString() + ':' + tcp.sport;
    let dst = ip.daddr.toString() + ':' + tcp.dport;


    // console.log('Qwduina',dns.question);
    // console.log('Aklsjdfgiosd', dns.answer);

    if (dns.answer.rrs.length > 0) {

        data.eventName = events.DNS_RESPONSE_EVENT;

        let domains = {};

        for (let i = 0; i < dns.answer.rrs.length; i++) {

            let name = dns.answer.rrs[i].name;
            let value = null;

            if (dns.answer.rrs[i].rdata) {
                value = dns.answer.rrs[i].rdata.toString();
            }

            if (!domains[name]) {
                domains[name] = [];
            }

            if (value) {
                domains[name].push(value)
            }

        }

        let cleanDomains = {};

        /**
         * Remove domains without data
         */
        Object.keys(domains).map((d) => {

            if (domains[d].length) {
                cleanDomains[d] = domains[d];
            }

        });

        data.domains = cleanDomains;

        data.id = DNS_IDS[dns.id];

        DNS_IDS[dns.id] = null;


    } else if (dns.question.rrs.length > 0) {

        let id = guid();

        DNS_IDS[dns.id] = id;

        data.eventName = events.DNS_REQUEST_EVENT;

        data.domain = dns.question.rrs[0].name;

        data.id = id;
        
    }

    data.src = src;
    data.dst = dst;

    return data;

}


/**
 * Parse mail data from raw packet
 * @param rawPacket
 */
function parseMail(rawPacket) {

    let ip = rawPacket.payload.payload;
    let tcp = rawPacket.payload.payload.payload;
    let dport = tcp.dport;

    let data = {
        eventName: events.MAIL_EVENT
    };

    let src = ip.saddr.toString() + ':' + tcp.sport;
    let dst = ip.daddr.toString() + ':' + tcp.dport;

    let sessionKey = `${src}::${dst}`;

    let isEncrypted = isMailConnectionEncrypted(dport);

    data.isEncrypted = isEncrypted;

    if(mailSessionData[sessionKey]){

        if(!isEncrypted && tcp.data){
            mailSessionData[sessionKey].data = Buffer
                .concat([mailSessionData[sessionKey].data, tcp.data])
        }

        return
    }

    data.protocol = getMailProtocol(dport);

    data.src = src;
    data.dst = dst;

    data.port = dport;
    
    if(!isEncrypted && tcp.data){

        data.data = tcp.data;
    }

    data.country = getCountry(rawPacket);

    mailSessionData[sessionKey] = data;

}

/**
 * Handle complete mail session
 * @param session
 */
function completeMailSession(session){

    let src = session.src_name;
    let dst = session.dst_name;

    var key = `${src}::${dst}`;

    if(mailSessionData[key]){

        let eventData = mailSessionData[key];

        if(!eventData.isEncrypted){
            eventData.data = eventData.data.toString('utf8', 0, eventData.data.length);
        }

        sendEvent(eventData);
        mailSessionData[key] = null;
    }

}


/**
 *
 * @param rawPacket
 * @returns {{eventName: string, src: string, dst: string}}
 */
function parseHTTPS(rawPacket) {

    let ip = rawPacket.payload.payload;
    let tcp = rawPacket.payload.payload.payload;
    let data = tcp.data;

    var src = ip.saddr.toString() + ':' + tcp.sport;
    var dst = ip.daddr.toString() + ':' + tcp.dport;

    if (data) {
        // var str = data.toString('utf8', 0, data.length);
        // console.log(str);
    }

    return {
        eventName: events.HTTPS_REQUEST_EVENT,
        src: src,
        dst: dst
    }

}


/**
 * Return mail protocol for given port
 * @param port
 */
function getMailProtocol(port){

    let protocol;

    if(POP_PORTS.indexOf(port) !== -1){
        protocol = 'POP';
    } else if(SMTP_PORTS.indexOf(port) !== -1){
        protocol = 'SMTP';
    } else if(IMAP_PORTS.indexOf(port) !== -1) {
        protocol = 'IMAP';
    }

    return protocol;

}


/**
 * Check is mail protocol encrypted by port
 * @param port
 * @returns {boolean}
 */
function isMailConnectionEncrypted(port){
    return ENCRYPTED_PORTS.indexOf(port) !== -1;
}


/**
 * Handle tcp packets
 * @param rawPacket
 * @param callback
 * @returns {null}
 */
function parsePacket(rawPacket, callback) {

    if (!rawPacket.payload || !rawPacket.payload.payload || !rawPacket.payload.payload.saddr || !rawPacket.payload.payload.payload) {
        return null
    }

    let tcp = rawPacket.payload.payload.payload;
    let dport = tcp.dport;
    let sport = tcp.sport;
    let decoderName = tcp.decoderName;

    let data = {};
    let parseData;

    if (decoderName === 'udp' && (sport === 53 || dport === 53)) {

        parseData = parseDNS(rawPacket);

    } else if (decoderName === 'tcp' && dport === 443) {

        parseData = parseHTTPS(rawPacket);

    } else if (decoderName === 'tcp' && MAIL_PORTS.indexOf(dport) !== -1){

        parseData = parseMail(rawPacket);

        return null;

    }

    data = Object.assign(data, parseData);

    data.country = getCountry(rawPacket);

    callback(data)

}