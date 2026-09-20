// A script whose comments describe something innocuous, but which
// actually creates a file at runtime - the JS equivalent of the
// Python fixture with the same name.
const fs = require('fs');
fs.writeFileSync('unexpected_marker_js.txt', "this file's existence is the point of the test");
console.log("Hello from JS!");
