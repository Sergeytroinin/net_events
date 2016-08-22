## Wrapper for node_pcap

Provide event-based interface, which allow get information about DNS, HTTP, HTTPS, POP/SMTP requests and responses

## Install

    npm install net_events

## Usage

```javascript
const Logger = require('net_events');
const events = Logger.events;

const logger = Logger.logger('wlan0');


logger.events.on(events.CONNECT_EVENT, (event) => {
    ...
});

```

### Ready

* Track start and end session
* Track dns request and response
* HTTPS events

### Changelog

### 0.0.7

* Unify data format for all events
* Fix dst and src for connect and disconnect events

## 0.0.6

* Fix folder to download

## 0.0.5

* Download Maxmind db when module starting first time
* Add ip to DNS
* Add Ready event

## 0.0.4

* Complete POP/SMTP/IMAP

## 0.0.3

* Fix double HTTP response
* Add fields to HTTP events data
* Add id to DNS request/response

## 0.0.2

* Ready handlers for HTTP, DNS, start and end of TCP session

## 0.0.1

* Just skeleton for module. Start watcher in separate process and send events in main process
