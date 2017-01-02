/*jshint esnext: true */
window.onload = function() {
    document.form.addEventListener("change", readfile, false);
    document.form.addEventListener("submit", send, false);
    var logs = document.getElementById("logs");
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

function formatHTMLCommonName(name, id) {
    return '<a href="/static/certsplainer.html?id=' + id + '">' + formatCommonName(name) + '</a>';
}

function formatCommonName(name) {
    let result = "";
    Object.keys(name).forEach((key) => {
        if (key != "id") {
            result += `/${key.toUpperCase()}=${name[key]}`;
        }
    });
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
    setField("issuer", formatHTMLCommonName(properties.issuer, properties.issuer.id));
    setField("notBefore", properties.validity.notBefore);
    setField("notAfter", properties.validity.notAfter);
    setField("subject", formatHTMLCommonName(properties.subject, properties.id));
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

    if (properties.x509v3Extensions.subjectAlternativeName && properties.x509v3Extensions.subjectAlternativeName.length > 0) {
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

    if (properties.ca && (properties.subject.cn == properties.issuer.cn)) {
        let trustTable = document.getElementById("trusttable");
        Object.keys(properties.validationInfo).forEach((trustStore) => {
            let tr = document.createElement("tr");
            let tdName = document.createElement("td");
            tdName.textContent = trustStore;
            tr.appendChild(tdName);
            let tdValue = document.createElement("td");
            if (properties.validationInfo[trustStore].isValid) {
                tdValue.innerHTML = '<img alt="true" src="/static/img/green-checkmark.png" width="50%" />';
            } else {
                tdValue.innerHTML = '<img alt="false" src="/static/img/red-checkmark.png" width="50%" />';
            }
            tr.appendChild(tdValue);
            trustTable.appendChild(tr);
        });
    } else {
        document.getElementById("trustheader").remove();
        document.getElementById("trusttable").remove();
    }

	setField("permalink", 'Displaying information for CN=' + properties.subject.cn + ' [<a href="/static/certsplainer.html?id=' + properties.id + '">permanent link</a>]');
    setField("title", 'certsplained ' + properties.subject.cn);
}

function addParentToCertPaths(cy, current, parent, depth) {
	console.log("current="+formatCommonName(current.certificate.subject), "parent="+formatCommonName(parent.certificate.subject));
	eles = cy.add(
        [
            {
                group: "nodes",
                data: { id: formatCommonName(parent.certificate.subject)},
                position: { x: 100*depth+50, y: 100*depth+50 }
            },
            {
                group: "edges",
                data: { source: formatCommonName(current.certificate.subject),
                        target: formatCommonName(parent.certificate.subject) }
            }
        ]);
	current = parent;
    if (current.parents) {
        for (var i = 0; i < current.parents.length; i++) {
            addParentToCertPaths(cy, current, current.parents[i], i+depth+1);
        }
    }
}

function drawCertPaths(json) {
	console.log("Drawing certificate paths");
	var cy = window.cy = cytoscape({
		container: document.getElementById('cy'),
		boxSelectionEnabled: false,
		autounselectify: true,
		layout: {
			name: 'grid'
		},
		style: [
			{
				selector: 'node',
				style: {
					'content': 'data(id)',
					'text-opacity': 0.7,
					'text-valign': 'center',
					'text-halign': 'right',
					'background-color': '#11479e'
				}
			},
			{
				selector: 'edge',
				style: {
					'width': 4,
					'target-arrow-shape': 'triangle',
					'line-color': '#9dbaea',
					'target-arrow-color': '#9dbaea',
					'curve-style': 'bezier'
				}
			}
		]
	});
	let current = json;
	cy.add({group: "nodes", data: {id: formatCommonName(current.certificate.subject)}, position: { x: 50, y: 50 }});
    if (current.parents) {
	    for (var i = 0; i < current.parents.length; i++) {
		    addParentToCertPaths(cy, current, current.parents[i], i+1);
    	}
    }
}

function getCertPaths(id) {
    let req = new Request("/api/v1/paths?id=" + id);
    return fetch(req)
        .then(function(response) {
            if (!response.ok) {
                logs.innerHTML = "Error: " + response.status + " " + response.statusText;
                logs.style.color = "Red";
                throw "Server error. Status: " + response.status + " " + response.statusText;
            }
            return response.json().then(function(json) {
				console.log(json);
                drawCertPaths(json);
            });
        })
        .catch(function(err) {
            logs.innerHTML = "Error when retrieving certificate paths: " + err;
            logs.style.color = "Red";
            throw "Could not retrieve certificate paths: " + err;
        });

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
                getCertPaths(json.id);
				logs.remove();
            });
        })
        .catch(function(err) {
            logs.innerHTML = "Error when loading certificate: " + err;
            logs.style.color = "Red";
            throw "Could not load certificate: " + err;
        });
}
	
function send(e) {
    e.preventDefault();
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
            getCertPaths(json.id);
			logs.remove();
        })
        .catch(function(err) {
            logs.innerHTML = "Error: " + err;
            logs.style.color = "Red";
        });
}
