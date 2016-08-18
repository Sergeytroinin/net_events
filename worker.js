'use strict';
const fs = require('fs'),
    zlib = require('zlib'),
    pcap = require('pcap'),
    maxmind = require('maxmind'),
    cookie = require('cookie'),
    DNS = require("pcap/decode/dns"),

    events = require('./events'),
    HTTPSession = require("./session"),

    lookup = maxmind.open('./GeoLite2-Country.mmdb', {
        cache: {
            max: 1000,
            maxAge: 1000 * 60 * 60
        }
    });


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

    process.send({
        eventName: eventData.eventName,
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
    httpSession.on("http error", function (s, d, error) {

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

            sendEvent({
                eventName: events.HTTP_REQUEST_EVENT,
                data: requestObject
            })

        }
    );


    httpSession.on("http response", function (session) {
        let req = session.response;

        responseObject.headers = req.headers;

        if (responseObject.headers['Cookie']) {
            responseObject.headers['Cookie'] = cookie.parse(responseObject.headers['Cookie'])
        }

        responseObject.url = req.headers['Host'] || req.headers['Server'];
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

        sendEvent({
            eventName: events.HTTP_RESPONSE_EVENT,
            data: responseObject
        })

    });

}


/**
 * Run observer
 * @param interfaceName
 */
function startObserve(interfaceName) {

    const tcpTracker = new pcap.TCPTracker(),
        pcapSession = pcap.createSession(interfaceName, "");

    tcpTracker.on('session', function (session) {

        onTCPSession(session);

        sendEvent({
            eventName: events.CONNECT_EVENT,
            src: session.src_name,
            dst: session.dst_name
        });

        session.on('end', function (session) {

            sendEvent({
                eventName: events.DISCONNECT_EVENT,
                src: session.src_name,
                dst: session.dst_name
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
    let tcp = rawPacket.payload.payload.payload;

    const dns = new DNS().decode(tcp.data, 0, tcp.data.length);


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

    return data;

}


/**
 * Check is packet contain mail login request
 * @param buffer
 * @returns {boolean}
 */
function isMailLoginRequest(buffer) {

    let decodedBuffer = buffer.toString('utf8', 0, buffer.length);

    return (/(LOGIN|login) /.test(decodedBuffer));

}


/**
 * Get content from mail request
 * @param buffer
 * @returns {*}
 */
function getMailRequestContent(buffer) {

    let decodedBuffer = buffer.toString('utf8', 0, buffer.length);
    let isAscii = true;

    for (let i = 0, len = decodedBuffer.length; i < len; i++) {
        if (buffer[i] > 127) {
            isAscii = false;
            break;
        }
    }

    if (isAscii) {
        return decodedBuffer;
    } else {
        return null;
    }

}


/**
 *
 * @param rawPacket
 */
function parseMail(rawPacket) {

    let tcp = rawPacket.payload.payload.payload;

    console.log(tcp);

    //noinspection JSUnresolvedVariable
    if (tcp.data_bytes) {
        if (isMailLoginRequest(tcp.data)) {
            let data = getMailRequestContent(tcp.data);
            if (data) {

                return {
                    eventName: events.MAIL_EVENT,
                    data: data
                }

            }
        }

    }

    return {}
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


var mailBuffer = new Buffer('');

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

    } else if (decoderName === 'tcp' && (dport === 143 || dport === 110)) {

        console.log('MAIl')

        parseData = parseMail(rawPacket);

    }  else if (rawPacket.payload.payload.payload.decoderName === 'tcp' &&
        (rawPacket.payload.payload.payload.dport === 993 ||
        rawPacket.payload.payload.payload.dport === 995)
    ) {

        let tcp = rawPacket.payload.payload.payload;

        if(tcp && tcp.data) {

            mailBuffer = Buffer.concat([mailBuffer, tcp.data])
            let str;
            try{
                str = zlib.unzipSync(mailBuffer).toString('utf8', 0, mailBuffer.length);
            }catch(e){
                str = ''
            }

            // console.log(mailBuffer);
            // console.log(str);

        }

        // console.log()
    }

    data = Object.assign(data, parseData);

    data.country = getCountry(rawPacket);

    callback(data)

}