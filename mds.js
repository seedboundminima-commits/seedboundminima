/**
 * Minima MDS JavaScript Library
 * Version: 2.1.0
 * 
 * This library provides access to the Minima blockchain through the MiniDapp System (MDS)
 */

(function() {
    // MDS object initialization
    var MDS = {
        // Callbacks
        mainCallback: null,
        
        // Initialize MDS
        init: function(callback) {
            MDS.mainCallback = callback;
            
            // Create WebSocket connection
            var host = window.location.hostname;
            var port = parseInt(window.location.port);
            var ws_port = port;
            
            // Connect to MDS
            var url = "wss://" + host + ":" + ws_port + "/";
            
            MDS.websocket = new WebSocket(url);
            
            MDS.websocket.onopen = function(evt) {
                // MDS is ready
                if(MDS.mainCallback) {
                    MDS.mainCallback({
                        event: "INITED",
                        data: {}
                    });
                }
            };
            
            MDS.websocket.onmessage = function(evt) {
                var msg = JSON.parse(evt.data);
                
                if(MDS.mainCallback) {
                    MDS.mainCallback(msg);
                }
            };
            
            MDS.websocket.onerror = function(evt) {
                console.error("WebSocket error:", evt);
            };
            
            MDS.websocket.onclose = function(evt) {
                console.log("WebSocket closed");
            };
        },
        
        // Send command to Minima
        cmd: function(command, callback) {
            var msg = {
                command: command
            };
            
            // Store callback
            if(callback) {
                var uid = Math.random().toString(36).substring(7);
                msg.uid = uid;
                MDS.callbacks[uid] = callback;
            }
            
            // Send message
            MDS.websocket.send(JSON.stringify(msg));
        },
        
        // Callback storage
        callbacks: {},
        
        // WebSocket connection
        websocket: null
    };
    
    // Make MDS globally available
    window.MDS = MDS;
})();


