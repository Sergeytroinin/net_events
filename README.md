## Wrapper for node_pcap

Provide event-based interface, which allow get information about DNS, HTTP, HTTPS, POP/SMTP requests and responses

## Install

    npm install net_events

## Usage

```javascript
const Logger = require('net_events');

const logger = Logger('wlan0');


logger.events.on('CONNECT_EVENT', (event) => {
    ...
});

```

### Ready

* Track start and end session
* Track dns request and response
* POP/SMTP
* HTTPS events