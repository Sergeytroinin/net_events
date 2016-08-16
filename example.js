'use strict';
const Logger = require('./index');

const events = require('./events');

const logger = Logger('wlan0');


logger.events.on(events.CONNECT_EVENT, (event) => {
    let data = event.data;
    console.log(`Session between ${data.src} and ${data.dst} started`)
});

logger.events.on(events.DISCONNECT_EVENT, (event) => {
    let data = event.data;
    console.log(`Session between ${data.src} and ${data.dst} ended`)
});

logger.events.on(events.DNS_REQUEST_EVENT, (event) => {
    console.log(event.data.domain)
});

logger.events.on(events.DNS_RESPONSE_EVENT, (event) => {
    console.log(event.data.domains)
});

logger.events.on(events.HTTP_REQUEST_EVENT, (event) => {
    console.log(event.data.data.headers)
});

logger.events.on(events.HTTP_RESPONSE_EVENT, (event) => {
    console.log(event.data.data.headers)
});

logger.events.on(events.HTTPS_REQUEST_EVENT, (data) => {
    console.log(data)
});
