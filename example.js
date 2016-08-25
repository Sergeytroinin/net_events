'use strict';
const Logger = require('./index');
const events = Logger.events;

const logger = Logger.logger('wlan0');


var DNS_DATA = {};
var CONNECT_DATA = {};


logger.events.on(events.READY_EVENT, () => {
    console.log('READY')
});

logger.events.on(events.CONNECT_EVENT, (event) => {
    let data = event.data;
    let key = `${data.src}::${data.dst}`;

    CONNECT_DATA[key] = {dst: data.dst, disconnect: false};

    // console.log(`Session between ${data.src} and ${data.dst} started`)
});

logger.events.on(events.DISCONNECT_EVENT, (event) => {
    let data = event.data;

    let key = `${data.src}::${data.dst}`;

    delete CONNECT_DATA[key];

    console.log(CONNECT_DATA[key]);

    // console.log(`Session between ${data.src} and ${data.dst} ended`)
});

logger.events.on(events.DNS_REQUEST_EVENT, (event) => {

    DNS_DATA[event.data.id] = {request: event.data};

    // console.log(event.data.id, event.data.domain)
});

logger.events.on(events.DNS_RESPONSE_EVENT, (event) => {

    DNS_DATA[event.data.id].response = event.data;

    // console.log(DNS_DATA[event.data.id])
});

logger.events.on(events.HTTP_REQUEST_EVENT, (event) => {
    // console.log('REQUEST', event)
});

logger.events.on(events.HTTP_RESPONSE_EVENT, (event) => {
    // console.log('RESPONSE', event)
});

logger.events.on(events.MAIL_EVENT, (data) => {
    console.log(data)
});

logger.events.on(events.RESET_EVENT, (data) => {
    console.log('RESET', data)
});
