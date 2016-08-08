'use strict';
const fork = require('child_process').fork;
const EventEmitter = require('events');

/**
 * Function which start observing for the traffic
 * @returns {{events: EventEmitter, finish: (())}}
 */
module.exports = function(interfaceName){

    const worker = fork(__dirname + '/worker.js');
    const emitter = new EventEmitter();

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
        emitter.emit(event.name, event.data)
    });

    /**
     * Process close on main process
     */
    process.on('close', () => {
        worker.kill()
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