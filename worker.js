'use strict';
var events = require('./events'),
// Session = require('./session'),
    CONNECT_EVENT = events.CONNECT_EVENT,
    DISCONNECT_EVENT = events.DISCONNECT_EVENT,

    DNS_REQUEST_EVENT = events.DNS_REQUEST_EVENT,
    DNS_RESPONSE_EVENT = events.DNS_RESPONSE_EVENT,

    HTTP_REQUEST_EVENT = events.HTTP_REQUEST_EVENT,
    HTTPS_REQUEST_EVENT = events.HTTPS_REQUEST_EVENT,
    HTTPS_RESPONSE_EVENT = events.HTTPS_RESPONSE_EVENT;

const DNS = require("pcap/decode/dns");
const maxmind = require('maxmind');

var lookup = maxmind.open('./GeoLite2-Country.mmdb', {
    cache: {
        max: 1000, // max items in cache
        maxAge: 1000 * 60 * 60 // life time in milliseconds
    }
});

var fs = require('fs');


var PacketStore = {};

function createSessionStore(options) {

    let id = `${options.src}::${options.dst}`;

    PacketStore[id] = {
        src: options.src,
        dst: options.dst,
        packets: []
    };

}


function clearSessionStore(options) {

    let id = `${options.src}::${options.dst}`;

    PacketStore[id] = null;

}


/**
 * Waiting for interface name and start observing
 */
process.on('message', (e) => {

    if (e.name === 'setInterface') {
        startObserve(e.data)
    }
});


/**
 * Send event to main process
 * @param eventData
 */
function sendEvent(eventData) {

    // console.log(eventData);

    process.send({
        eventName: eventData.eventName,
        data: eventData
    })
}


/**
 * Run observer
 * @param interfaceName
 */
function startObserve(interfaceName) {

    var pcap = require('pcap'),
        tcp_tracker = new pcap.TCPTracker(),
        pcap_session = pcap.createSession(interfaceName, "");

    tcp_tracker.on('session', function (session) {

        var b = new Buffer('');


        sendEvent({
            eventName: CONNECT_EVENT,
            src: session.src_name,
            dst: session.dst_name

        });

        session.on('data recv', (s, buf) => {

            b = Buffer.concat([b, buf]);


        });


        // session.on('retransmit', (s, h) => {
        //
        //     console.log('HTTP ljsdkfauibfvhi;aosdbhfi[o')
        //
        // })

        session.on('end', function (session) {

            // console.log(b);
            //
            // console.log(b.toString('utf8', 0, b.length));
            //
            // fs.writeFileSync(`${Math.random()}.html`, b.toString('utf8', 0, b.length));


            sendEvent({
                eventName: DISCONNECT_EVENT,
                src: session.src_name,
                dst: session.dst_name

            });
        });

    });

    pcap_session.on('packet', function (raw_packet) {
        var packet = pcap.decode.packet(raw_packet);

        parsePacket(packet, sendEvent);

        tcp_tracker.track_packet(packet);
    });


}


function getCountry(rawPacket) {

    var ip = rawPacket.payload.payload.saddr.addr.join('.');

    var geoData = lookup.get(ip);

    if (geoData && geoData.country && geoData.country.names) {
        return geoData.country.names.en;
    } else {
        return 'Unrecognized';
    }

}


function parseDNS(rawPacket) {

    let data = {};

    var dns = new DNS().decode(rawPacket.payload.payload.payload.data, 0, rawPacket.payload.payload.payload.data.length);

    if (dns.answer.rrs.length > 0) {

        data.eventName = DNS_RESPONSE_EVENT;

        let domains = {};

        for (var i = 0; i < dns.answer.rrs.length; i++) {

            let name = dns.answer.rrs[i].name;
            let value = null;

            if (dns.answer.rrs[i].rdata) {
                value = dns.answer.rrs[i].rdata.toString();
            }

            if (!domains[name]) {
                domains[name] = [];
            }

            if (value) domains[name].push(value)

        }

        let cleanDomains = {};

        Object.keys(domains).map((d) => {

            if (domains[d].length) {
                cleanDomains[d] = domains[d];
            }

        });

        data.domains = cleanDomains;

    } else if (dns.question.rrs.length > 0) {

        data.eventName = DNS_REQUEST_EVENT;

        data.domain = dns.question.rrs[0].name;

    }

    return data;

}


function parseHTTP(rawPacket) {

    // console.log(rawPacket.payload.payload);

    var src = rawPacket.payload.payload.saddr.addr.join('.') + ':' + rawPacket.payload.payload.payload.sport;
    var dst = rawPacket.payload.payload.daddr.addr.join('.') + ':' + rawPacket.payload.payload.payload.dport;


    // console.log(`from ${src} to ${dst}`);

    var tcp = rawPacket.payload.payload.payload;

    if (tcp.data) {
        var buf = tcp.data;
        var str = buf.toString('utf8', 0, buf.length);

        // console.log(str);
    } else {
        // console.log(rawPacket.payload.payload)
    }


    return {
        eventName: HTTP_REQUEST_EVENT,
        data: {}
    }

}


var detect_mail_login_request = function (buf) {
    var str = buf.toString('utf8', 0, buf.length);

    return (/(LOGIN|login) /.test(str));
};


var mail_request_content = function (buf) {
    var str = buf.toString('utf8', 0, buf.length);
    var isAscii = true;
    for (var i = 0, len = str.length; i < len; i++) {
        if (buf[i] > 127) {
            isAscii = false;
            break;
        }
    }
    if (isAscii)
        return str;
    return null;

};


function parseMail(rawPacket) {

    var tcp = rawPacket.payload.payload.payload;

    if (tcp.data_bytes) {
        if (detect_mail_login_request(tcp.data)) {
            var data = mail_request_content(tcp.data);
            if (data) {

            }
        }


    }
}


function parseHTTPS(rawPacket) {

    // console.log(rawPacket.payload.payload);

    let data = rawPacket.payload.payload.payload.data;

    var src = rawPacket.payload.payload.saddr.toString() + ':' + rawPacket.payload.payload.payload.sport;
    var dst = rawPacket.payload.payload.daddr.toString() + ':' + rawPacket.payload.payload.payload.dport;

    if (data) {
        var str = data.toString('utf8', 0, data.length);
        // console.log(str);
    }

    return {
        eventName: HTTPS_REQUEST_EVENT,
        src: src,
        dst: dst
    }
}


function parsePacket(rawPacket, callback) {

    if (!rawPacket.payload || !rawPacket.payload.payload || !rawPacket.payload.payload.saddr || !rawPacket.payload.payload.payload) {
        return null
    }

    let data = {};
    let parseData;

    if (rawPacket.payload.payload.payload.decoderName === 'udp' &&
        (rawPacket.payload.payload.payload.sport === 53 ||
        rawPacket.payload.payload.payload.dport === 53)) {

        parseData = parseDNS(rawPacket);

    } else if (rawPacket.payload.payload.payload.decoderName === 'tcp' &&
        rawPacket.payload.payload.payload.dport === 80) {

        parseData = parseHTTP(rawPacket);

    } else if (rawPacket.payload.payload.payload.decoderName === 'tcp' &&
        rawPacket.payload.payload.payload.dport === 443) {

        parseData = parseHTTPS(rawPacket)

    } else if (rawPacket.payload.payload.payload.decoderName === 'tcp' &&
        (rawPacket.payload.payload.payload.dport === 143 ||
        rawPacket.payload.payload.payload.dport === 110)) {

        parseData = parseMail(rawPacket)

    }


    data = Object.assign(data, parseData);

    data.country = getCountry(rawPacket);

    // console.log(data.country);

    callback(data)

}