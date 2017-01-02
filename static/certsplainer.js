/*jshint esnext: true */
window.onload = function() {
    document.form.addEventListener("change", readfile, false);
    document.form.addEventListener("submit", send, false);
	let certid = getParameterByName('id');
	let certsha256 = getParameterByName('sha256');
	if (certid || certsha256) {
		loadCert(certid, certsha256);
	}
};

function getParameterByName(name, url) {
    if (!url) {
      url = window.location.href;
    }
    name = name.replace(/[\[\]]/g, "\\$&");
    var regex = new RegExp("[?&]" + name + "(=([^&#]*)|&|#|$)"),
        results = regex.exec(url);
    if (!results) return null;
    if (!results[2]) return '';
    return decodeURIComponent(results[2].replace(/\+/g, " "));
}

function readfile(e) {
    var reader = new FileReader();
    reader.addEventListener("loadend", function(event) {
        document.getElementById("certificate").value = event.target.result;
    }, false);
    reader.readAsText(e.target.files[0]);
}

function postCertificate(certificate) {
    let data = [];
    for (let i = 0; i < certificate.length; i++) {
        data.push(certificate[i]);
    }
    let blob = new Blob(data);
    let formdata = new FormData();
    formdata.append("certificate", blob);

    let reqInit = {
        method: "POST",
        body: formdata
    };
    let req = new Request("/api/v1/certificate");
    return fetch(req, reqInit)
        .then(function(response) {
            if (!response.ok) {
                logs.innerHTML = "Error: " + response.status + " " + response.statusText;
                logs.style.color = "Red";
                throw "Server error. Status: " + response.status + " " + response.statusText;
            }
            return response.json().then(function(json) {
                return json;
            });
        })
        .catch(function(err) {
            logs.innerHTML = "Error when posting certificate: " + err;
            logs.style.color = "Red";
            throw "Could not post certificate: " + err;
        });
}

function setField(field, value) {
    document.getElementById(field).innerHTML = value;
}

function clearFields() {
    for (let id of ["version", "serialNumber", "issuer", "notBefore", "notAfter",
			"subject", "signatureAlgorithm", "keySize", "exponent", "curve",
			"sha1hash", "sha256hash", "sha256_subject_spki", "pin-sha256", "id",
			"permalink", "help"
        ]) {
        setField(id, "");
    }
    document.getElementById("curveRow").classList.remove("hidden");
    document.getElementById("keySizeRow").classList.remove("hidden");
    document.getElementById("exponentRow").classList.remove("hidden");
}

function clearExtensions() {
    let extensionsTable = document.getElementById("extensions");
    while (extensionsTable.children.length > 0) {
        extensionsTable.children[0].remove();
    }
}

function formatCommonName(name, id) {
    let result = '<a href="/static/certsplainer.html?id=' + id + '">';
    Object.keys(name).forEach((key) => {
        if (key != "id") {
            result += `/${key.toUpperCase()}=${name[key]}`;
        }
    });
	result += '</a>';
    return result;
}

function formatExtension(extensionName, extension) {
    if (extensionName == "authorityKeyId" || extensionName == "subjectKeyId") {
        let bin = atob(extension);
        let hexStr = "";
        for (let i = 0; i < bin.length; i++) {
            hexStr += bin.charCodeAt(i).toString(16).padStart(2, "0");
        }
        return hexStr;
    }

    return extension.toString();
}

function setFieldsFromJSON(properties) {
    clearFields();
    clearExtensions();

    if (!properties) {
        return;
    }

    console.log(properties);

    setField("version", properties.version);
    setField("serialNumber", properties.serialNumber.toLowerCase());
    setField("issuer", formatCommonName(properties.issuer, properties.issuer.id));
    setField("notBefore", properties.validity.notBefore);
    setField("notAfter", properties.validity.notAfter);
    setField("subject", formatCommonName(properties.subject, properties.id));
    setField("signatureAlgorithm", properties.signatureAlgorithm); // TODO technically there are two fields here...
    if (properties.key.alg == "RSA") {
        setField("keySize", properties.key.size);
        setField("exponent", properties.key.exponent);
        document.getElementById("curveRow").classList.add("hidden");
    } else {
        setField("curve", properties.key.curve);
        document.getElementById("keySizeRow").classList.add("hidden");
        document.getElementById("exponentRow").classList.add("hidden");
    }
    setField("sha1hash", properties.hashes.sha1.toLowerCase());
    setField("sha256hash", properties.hashes.sha256.toLowerCase());
    setField("sha256_subject_spki", properties.hashes.sha256_subject_spki.toLowerCase());
    setField("pin-sha256", properties.hashes['pin-sha256'].toLowerCase());
    setField("id", '<a href="/api/v1/certificate?id=' + properties.id + '">' + properties.id + '</a>');

    let extensionsTable = document.getElementById("extensions");
    Object.keys(properties.x509v3Extensions).forEach((extensionName) => {
		if (extensionName == 'subjectAlternativeName') {
			return;
		}
        let extension = properties.x509v3Extensions[extensionName];
        if (!extension) {
            return;
        }
        let tr = document.createElement("tr");
        let tdName = document.createElement("td");
        tdName.textContent = extensionName;
        tr.appendChild(tdName);
        let tdValue = document.createElement("td");
        tdValue.textContent = formatExtension(extensionName, extension);
        tr.appendChild(tdValue);
        extensionsTable.appendChild(tr);
    });

    if (properties.x509v3BasicConstraints) {
        let tr = document.createElement("tr");
        let tdName = document.createElement("td");
        tdName.textContent = "basicConstraints";
        tr.appendChild(tdName);
        let tdValue = document.createElement("td");
        tdValue.textContent = `CA:${properties.ca}`;
        tr.appendChild(tdValue);
        extensionsTable.appendChild(tr);
    }

    if (properties.x509v3Extensions.subjectAlternativeName) {
        let sanTable = document.getElementById("santable");
        Object.keys(properties.x509v3Extensions.subjectAlternativeName).forEach((sanID) => {
            let tr = document.createElement("tr");
            let tdValue = document.createElement("td");
            tdValue.textContent = properties.x509v3Extensions.subjectAlternativeName[sanID];
            tr.appendChild(tdValue);
            sanTable.appendChild(tr);
        });
    } else {
        document.getElementById("sanheader").remove();
        document.getElementById("santable").remove();
    }

	setField("permalink", 'Displaying information for CN=' + properties.subject.cn + ' [<a href="/static/certsplainer.html?id=' + properties.id + '">permanent link</a>]');
    setField("title", 'certsplained ' + properties.subject.cn);
}

function loadCert(id, sha256) {
    let req = new Request("/api/v1/certificate?id=" + id);
	if (sha256) {
		req = new Request("/api/v1/certificate?sha256=" + sha256);
	}
    return fetch(req)
        .then(function(response) {
            if (!response.ok) {
                logs.innerHTML = "Error: " + response.status + " " + response.statusText;
                logs.style.color = "Red";
                throw "Server error. Status: " + response.status + " " + response.statusText;
            }
            return response.json().then(function(json) {
            	setFieldsFromJSON(json);
				logs.remove();
            });
        })
        .catch(function(err) {
            logs.innerHTML = "Error when posting certificate: " + err;
            logs.style.color = "Red";
            throw "Could not post certificate: " + err;
        });
}
	
function send(e) {
    e.preventDefault();
    var logs = document.getElementById("logs");
    logs.style.color = "Blue";
    logs.innerHTML = "Certificate posted, waiting for result...";
    console.log("Posting certificate for analysis");

    var certificate = document.getElementById("certificate").value;
    certificate = certificate.trim();
    if (!certificate.startsWith("-----BEGIN CERTIFICATE-----") || !certificate.endsWith("-----END CERTIFICATE-----")) {
        err = "Invalid certificate format, must be PEM encoded";
        logs.innerHTML = "Error: " + err;
        logs.style.color = "Red";
        throw err;
    }

    return postCertificate(certificate).
    then(function(certJson) {
            setFieldsFromJSON(certJson);
			logs.remove();
        })
        .catch(function(err) {
            logs.innerHTML = "Error: " + err;
            logs.style.color = "Red";
        });
}
