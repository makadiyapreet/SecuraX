const { exec } = require('child_process');

function runDiagnostic(userHost) {
    exec("nslookup " + userHost, (err, stdout) => {
        console.log(stdout);
    });
}
