window.onload = function() {
    document.form.addEventListener("submit", send, false);
    document.form.addEventListener("change", readfile, false);
}

function checkResult(id) {
    return fetch("/api/v1/results?id=" + id)
	.then(function(response) {
            return response.json().then(function(json) {
		let completion_percent = json.completion_perc;
		if (completion_percent !== 100) {
                    console.log("Not done yet, running again");
                    var result = document.getElementById("result");
                    result.innerHTML += ".";
		    return new Promise(resolve => setTimeout(resolve, 1000)).then(function() { return checkResult(id) });
		}
                return Promise.resolve(json.analysis.find(analysis => analysis.analyzer == "ev-checker"));
            });
	});
}

function startScan(target, oid, rootCertificate) {
    result.style.color = "Blue";

    // clean up leading and trailing whitespaces
    target = target.trim();
    oid = oid.trim();
    rootCertificate = rootCertificate.trim();

    if (!/^(([0-9]+)\.?)+$/.test(oid)) {
        err = "Invalid OID format, must respect regular expression '^([0-9]+)\.?$'";
        result.innerHTML = "Error: " + err;
        result.style.color = "Red";
        throw err;
    }
    if (!rootCertificate.startsWith("-----BEGIN CERTIFICATE-----") || !rootCertificate.endsWith("-----END CERTIFICATE-----")) {
        err = "Invalid certificate format, must be PEM encoded";
        result.innerHTML = "Error: " + err;
        throw err;
    }
    let params = {
	"ev-checker": {
	    "oid": oid,
	    "rootCertificate": rootCertificate
	}
    };
    let queryParams = {
	"rescan": true,
	"target": hostname_from(target),
	"params": JSON.stringify(params)
    };
    let query = Object.keys(queryParams)
	.map(k => encodeURIComponent(k) + '=' + encodeURIComponent(queryParams[k]))
	.join('&');
    let url = "/api/v1/scan?" + query
    return fetch(url, {method: "POST"}).then(function(response) {
        if (!response.ok) {
            throw "Server error. Status: " + response.status + " " + response.statusText; 
        }
	return response.json().then(function(json) {
	    return json.scan_id;
	});
    })
	.catch(function(err) {
            throw "Could not initiate scan: " + err;
	});
}

function send(e) {
    e.preventDefault();
    var target = document.getElementById("target").value;
    var oid = document.getElementById("oid").value;
    var rootCertificate = document.getElementById("rootCertificate").value;
    var result = document.getElementById("result");
    startScan(target, oid, rootCertificate).then(function(id) {
        console.log("Scan started with id", id);
        result.innerHTML = "Scan started, waiting for result...";
        return checkResult(id).then(function(params) {
	    if (params.success) {
                result.innerHTML = "ev-checker exited successfully: " + params.result;
                result.style.color = "Green";
	    } else {
                result.innerHTML = "ev-checker reported failure: " + params.result;
                result.style.color = "Red";
	    }
        });
    })
	.catch(function(err) {
            result.innerHTML = "Error: " + err;
            result.style.color = "Red";
	});
}

function hostname_from(target) {
    // if target is a URI, extract hostname from it
    if (target.startsWith("http") == true) {
        let targetParser = document.createElement('a');
        targetParser.href = target;
        return targetParser.hostname;
    } else {
        return target;
    }
}

function readfile(e) {
    var reader = new FileReader();
    reader.addEventListener("loadend", function(event) {
        document.getElementById("rootCertificate").value = event.target.result;
    }, false);
    reader.readAsText(e.target.files[0])
}
