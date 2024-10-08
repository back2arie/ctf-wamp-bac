var autobahn = require('autobahn');

url = 'ws://localhost:8080/ws';
// url = 'ws://117.53.46.91:8080/ws';
authid = 'user1';
key = 'user-password';
procedure = 'ctf.wamp.get_flag';

var connection = new autobahn.Connection({
    url: url,
    realm: 'realm1',
    authmethods: ["wampcra", "anonymous"],
    authid: authid,
    onchallenge: function (session, method, extra) {
        if (method === "wampcra") {
            return autobahn.auth_cra.sign(key, extra.challenge);
        }
    }
});

connection.onopen = function (session) {
    console.log('Call remote procedure: ' + procedure);
    session.call(procedure, [], {}, {}).then(
        function (res) {
           console.log("Result: ", res);
        }
     );
};

connection.open();