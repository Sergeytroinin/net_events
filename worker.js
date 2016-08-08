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
    process.send({
        name: eventData.name,
        data: eventData.data
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


        // var s = new Session(session);

        // var body = new Buffer('');
        //
        // s.on('http response body', (a, data) => {
        //     console.log('PACKET');
        //     body = Buffer.concat([body, data]);
        //     // console.log(a)
        // });
        //
        // s.on('http response complete', (data) => {
        //     console.log(body.toString())
        // });

        sendEvent({
            name: CONNECT_EVENT,
            data: {
                src: session.src_name,
                dst: session.dst_name
            }
        });

        session.on('end', function (session) {
            sendEvent({
                name: DISCONNECT_EVENT,
                data: {
                    src: session.src_name,
                    dst: session.dst_name
                }
            });
        });

    });

    pcap_session.on('packet', function (raw_packet) {
        var packet = pcap.decode.packet(raw_packet);


        // console.log(raw_packet)

        var buf = raw_packet.buf;

        var str = buf.toString('utf8', 0, buf.length);

        // console.log(str);

        parsePacket(packet, (data) => {

            sendEvent({
                name: data.eventName,
                data: data
            })

        });

        tcp_tracker.track_packet(packet);
    });


}


function getCountryByIP(rawPacket){

    var ip = rawPacket.payload.payload.saddr.addr.join('.');

    var geoData = lookup.get(ip);

    if(geoData && geoData.country && geoData.country.names){
        return geoData.country.names.en;
    } else {
        return 'Unrecognized';
    }

}


function parseDNS(rawPacket) {

    let data = {};

    var dns = new DNS().decode(rawPacket.payload.payload.payload.data, 0, rawPacket.payload.payload.payload.data.length);

    // console.log(dns.answer)

    if (dns.answer.rrs.length > 0) {

        data.eventName = DNS_RESPONSE_EVENT;



    } else if (dns.question.rrs.length > 0) {

        data.eventName = DNS_REQUEST_EVENT;

        console.log(dns.question.rrs);

        for (var i=0; i < dns.question.rrs.length; i++) {
            console.log(dns.question.rrs[i].name)

            console.log(dns.question.rrs[i].rdata)
        }

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


function parseHTTPS(rawPacket) {

    // console.log(rawPacket.payload.payload.payload);

    return {
        eventName: HTTPS_REQUEST_EVENT,
        data: {}
    }
}


function parsePacket(rawPacket, callback) {

    if (!rawPacket.payload ||
        !rawPacket.payload.payload ||
        !rawPacket.payload.payload.saddr ||
        !rawPacket.payload.payload.payload) {
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

    }

    data = Object.assign(data, parseData);

    data.country = getCountryByIP(rawPacket);

    // console.log(data.country);

    callback(data)

}