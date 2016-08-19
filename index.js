'use strict';
const fork = require('child_process').fork;
const EventEmitter = require('events');
const http = require('http');
const fs = require('fs');
const events = require('./events');
const zlib = require('zlib');

var maxMindSrc = 'http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.mmdb.gz';

/**
 * Function which get and unpack Maxmind db
 * @param url
 * @param dest
 * @param out
 * @param cb
 */
function downloadMaxmindDatabase(url, dest, out, cb) {

    if(fs.existsSync(out)){
        cb();
        return;
    }

    http.get(url, (response) => {

        // let src = fs.createWriteStream(dest);
        //
        // response.pipe(src);
        //
        // src.on('finish', () => {
        //
        //     src.close(() => {
        //
        //         let file = fs.createReadStream(dest);
        //
        //         let output = fs.createWriteStream(out);
        //
        //         file.pipe(zlib.createUnzip()).pipe(output);
        //
        //         file.on('finish', () => {
        //             file.close(cb)
        //         });
        //
        //     })
        //
        // })

        let output = fs.createWriteStream(out);

        response.pipe(zlib.createUnzip()).pipe(output);
        
        output.on('finish', cb)

    });
}


/**
 * Function which start observing for the traffic
 * @returns {{events: EventEmitter, finish: (())}}
 */
var logger = function (interfaceName) {

    const MAXMIND_FILENAME = __dirname + '/GeoLite2-Country.mmdb';
    const MAXMIND_FILENAME_GZ = __dirname + '/GeoLite2-Country.mmdb.gz';

    const worker = fork(__dirname + '/worker.js');
    const emitter = new EventEmitter();

    downloadMaxmindDatabase(maxMindSrc, MAXMIND_FILENAME_GZ, MAXMIND_FILENAME, () => {

        console.log('sdfsdf')

        emitter.emit(events.READY_EVENT, {});

        /**
         * Set network interface
         */
        worker.send({
            name: 'setInterface',
            data: interfaceName
        });

        /**
         * Process event from worker
         */
        worker.on('message', (event) => {
            emitter.emit(event.eventName, event)
        });

        /**
         * Process close on main process
         */
        process.on('close', () => {
            worker.kill()
        });

    });


    /**
     * Manually kill worker
     */
    const finish = () => {
        worker.kill();
    };

    return {
        events: emitter,
        finish: finish
    }

};

module.exports = {
    logger: logger,
    events: events
};