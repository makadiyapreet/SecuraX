const { execFile } = require('child_process');

function runDiagnostic(userHost) {
    execFile("nslookup", [userHost], (err, stdout) => {
        console.log(stdout);
    });
}
