/*jshint esnext: true */

var logs = undefined;

window.onload = function() {
    document.form.addEventListener('change', readfile, false);
    document.form.addEventListener('submit', send, false);
    logs = document.getElementById('logs');
    let certid = getParameterByName('id');
    let certsha256 = getParameterByName('sha256');
    if (certid || certsha256) {
        loadCert(certid, certsha256);
    } else {
        logs.textContent = 'No certificate found to analyze.';
    }
};

function getParameterByName(name, url) {
    if (!url) {
        url = window.location.href;
    }
    name = name.replace(/[\[\]]/g, '\\$&');
    let regex = new RegExp('[?&]' + name + '(=([^&#]*)|&|#|$)'),
        results = regex.exec(url);
    if (!results) {
        return null;
    }
    if (!results[2]) {
        return '';
    }
    return decodeURIComponent(results[2].replace(/\+/g, ' '));
}

// if the cert is DER encoded (doesn't start with PEM header), base64 encode
// it and add the header and footer
function possiblyBinaryToPEM(possiblyBinary) {
    if (!possiblyBinary.startsWith("-----BEGIN CERTIFICATE-----")) {
        return "-----BEGIN CERTIFICATE-----\n" + btoa(possiblyBinary).replace(/(\S{64}(?!$))/g, "$1\n") + "\n-----END CERTIFICATE-----";
    }
    return possiblyBinary;
}

function readfile(e) {
    let reader = new FileReader();
    reader.addEventListener('loadend', function(event) {
        let buffer = new Uint8Array(event.target.result);
        let data = "";
        for (let i = 0; i < buffer.length; i++) {
            data += String.fromCharCode(buffer[i]);
        }
        let pem = possiblyBinaryToPEM(data);
        document.getElementById('certificate').value = pem;
        // dispatch event to form submit
        var submitEvent = new Event('submit');
        send(submitEvent);
    }, false);
    reader.readAsArrayBuffer(e.target.files[0]);
}

function postCertificate(certificate) {
    let data = [];
    for (let i = 0; i < certificate.length; i++) {
        data.push(certificate[i]);
    }
    let blob = new Blob(data);
    let formdata = new FormData();
    formdata.append('certificate', blob);

    let reqInit = {
        method: 'POST',
        body: formdata
    };
    let req = new Request('/api/v1/certificate');
    return fetch(req, reqInit)
        .then(function(response) {
            if (!response.ok) {
                logs.textContent = 'Error: ' + response.status + ' ' + response.statusText;
                logs.style.color = 'Red';
                throw 'Server error. Status: ' + response.status + ' ' + response.statusText;
            }
            return response.json().then(function(json) {
                return json;
            });
        })
        .catch(function(err) {
            logs.textContent = 'Error when posting certificate: ' + err;
            logs.style.color = 'Red';
            throw 'Could not post certificate: ' + err;
        });
}

function setField(field, value) {
    let node = document.getElementById(field);

    switch (typeof value) {
    case 'number':
    case 'string':
	// Setting textContent removes all child nodes
	node.textContent = value;
	break;

    case 'object':
	let newNode = node.cloneNode(false);
	newNode.appendChild(value);
	node.parentNode.replaceChild(newNode, node);
	break;

    default:
	console.log("setField(): Unexpected type '" + typeof(value) + "'");
    }
}

function clearFields() {
    for (let id of ['version', 'serialNumber', 'issuer', 'notBefore', 'notAfter',
        'subject', 'signatureAlgorithm', 'keySize', 'exponent', 'curve',
        'sha1hash', 'sha256hash', 'spki-sha256', 'subject-spki-sha256', 'pin-sha256',
        'id', 'permalink', 'help'
    ]) {
        setField(id, '');
    }

    for (let id of ['curveRow', 'keySizeRow', 'exponentRow']) {
	document.getElementById(id).classList.remove('hidden');
    }
}

function clearTable(name) {
    let tb = document.getElementById(name);
    while (tb.children.length > 0) {
        tb.children[0].remove();
    }
}

function permanentLink(id, text) {
    let link = document.createElement('a');
    link.setAttribute('href', "/static/certsplainer.html?id=" + id);
    link.textContent = text;
    return link;
}

function formatHTMLCommonName(name, id) {
    return permanentLink(id, formatCommonName(name));
}

function formatCommonName(name) {
    let result = '';
    Object.keys(name).forEach((key) => {
        if (key !== 'id') {
            result += `/${key.toUpperCase()}=${name[key]}`;
        }
    });
    return result;
}

function formatExtension(extensionName, extension) {
    if (extensionName === 'authorityKeyId' || extensionName === 'subjectKeyId') {
        let bin = atob(extension);
        let hexStr = '';
        for (let i = 0; i < bin.length; i++) {
            let comp = bin.charCodeAt(i).toString(16);
            if (comp.length === 1) {
                comp = '0' + comp;
            }
            hexStr += comp;
        }
        return hexStr;
    }

    return extension.toString();
}

function setFieldsFromJSON(properties) {
    clearFields();
    clearTable('extensions');
    clearTable('santable');
    clearTable('trusttable');
    if (!properties) {
        return;
    }
    setField('version', properties.version);
    setField('serialNumber', properties.serialNumber.toLowerCase());
    setField('issuer', formatHTMLCommonName(properties.issuer, properties.issuer.id));
    setField('notBefore', properties.validity.notBefore);
    setField('notAfter', properties.validity.notAfter);
    setField('subject', formatHTMLCommonName(properties.subject, properties.id));
    setField('signatureAlgorithm', properties.signatureAlgorithm);
    if (properties.key.alg === 'RSA') {
        setField('keySize', properties.key.size);
        setField('exponent', properties.key.exponent);
        document.getElementById('curveRow').classList.add('hidden');
    } else {
        setField('curve', properties.key.curve);
        document.getElementById('keySizeRow').classList.add('hidden');
        document.getElementById('exponentRow').classList.add('hidden');
    }
    setField('sha1hash', properties.hashes.sha1.toUpperCase());
    setField('sha256hash', properties.hashes.sha256.toUpperCase());
    setField('spki-sha256', properties.hashes['spki-sha256'].toUpperCase());
    setField('subject-spki-sha256', properties.hashes['subject-spki-sha256'].toUpperCase());
    setField('pin-sha256', properties.hashes['pin-sha256'].toUpperCase());
    setField('id', permanentLink(properties.id, properties.id));
    setField('certificate', "-----BEGIN CERTIFICATE-----\n" + properties.Raw.replace(/(\S{64}(?!$))/g, "$1\n") + "\n-----END CERTIFICATE-----" );

    let extensionsTable = document.getElementById('extensions');
    Object.keys(properties.x509v3Extensions).forEach((extensionName) => {
        if (extensionName === 'subjectAlternativeName') {
            return;
        }
        let extension = properties.x509v3Extensions[extensionName];
        if (!extension) {
            return;
        }
        let tr = document.createElement('tr');
        let tdName = document.createElement('td');
        tdName.textContent = extensionName;
        tr.appendChild(tdName);
        let tdValue = document.createElement('td');
        tdValue.textContent = formatExtension(extensionName, extension);
        tr.appendChild(tdValue);
        extensionsTable.appendChild(tr);
    });

    if (properties.x509v3BasicConstraints) {
        let tr = document.createElement('tr');
        let tdName = document.createElement('td');
        tdName.textContent = 'basicConstraints';
        tr.appendChild(tdName);
        let tdValue = document.createElement('td');
        tdValue.textContent = `CA:${properties.ca}`;
        tr.appendChild(tdValue);
        extensionsTable.appendChild(tr);
    }

    if (properties.x509v3Extensions.subjectAlternativeName && properties.x509v3Extensions.subjectAlternativeName.length > 0) {
        let sanTable = document.getElementById('santable');
        sanTable.style.display = 'block';
        document.getElementById('sanheader').style.display = 'block';
        Object.keys(properties.x509v3Extensions.subjectAlternativeName).forEach((sanID) => {
            let tr = document.createElement('tr');
            let tdValue = document.createElement('td');
            tdValue.textContent = properties.x509v3Extensions.subjectAlternativeName[sanID];
            tr.appendChild(tdValue);
            sanTable.appendChild(tr);
        });
    } else {
        document.getElementById('sanheader').style.display = 'none';
        document.getElementById('santable').style.display = 'none';
    }

    if (properties.ca && (properties.subject.cn === properties.issuer.cn)) {
        let trustTable = document.getElementById('trusttable');
        trustTable.style.display = 'block';
        document.getElementById('trustheader').style.display = 'block';
        Object.keys(properties.validationInfo).forEach((trustStore) => {
            let tr = document.createElement('tr');
            let tdName = document.createElement('td');
            tdName.textContent = trustStore;
            tr.appendChild(tdName);
            let tdValue = document.createElement('td');
            if (properties.validationInfo[trustStore].isValid) {
                tdValue.innerHTML = '<img alt="true" src="/static/img/green-checkmark.png" width="50%" />';
            } else {
                tdValue.innerHTML = '<img alt="false" src="/static/img/red-checkmark.png" width="50%" />';
            }
            tr.appendChild(tdValue);
            trustTable.appendChild(tr);
        });
    } else {
        document.getElementById('trustheader').style.display = 'none';
        document.getElementById('trusttable').style.display = 'none';
    }

    let permalink = permanentLink(properties.id, 'permanent link');
    let permatext = document.createElement(null);
    permatext.appendChild(document.createTextNode('Displaying information for CN=' + properties.subject.cn + ' ['));
    permatext.appendChild(permalink);
    permatext.appendChild(document.createTextNode(']'));

    setField('permalink',  permatext);
    setField('title', 'certsplained ' + properties.subject.cn);
	window.history.replaceState({}, "", [location.protocol, '//', location.host, location.pathname].join('') + '?id=' + properties.id);
}

function addParentToCertPaths(current, parent, x, y) {
    let eles = cy.add([
        {
            group: 'nodes',
            data: { id: formatCommonName(parent.certificate.subject)},
            position: { x: x, y: y}
        },
        {
            group: 'edges',
            data: { source: formatCommonName(current.certificate.subject),
                target: formatCommonName(parent.certificate.subject) }
        }
    ]);
    if (parent.certificate.ca) {
        if (parent.certificate.subject.cn === parent.certificate.issuer.cn) {
            // this is a root CA, show it red
            eles.style({'background-color': '#bd0000'});
        } else {
            // intermediate, use green
            eles.style({'background-color': '#009600'});
        }
    }
    current = parent;
    if (current.parents) {
        y += 150;
        for (var i = 0; i < current.parents.length; i++) {
            y += 20;
            addParentToCertPaths(current, current.parents[i], x + i*100 + 70, y);
        }
    }
}

function drawCertPaths(json) {
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
                    'text-opacity': 1,
                    'text-valign': 'center',
                    'text-halign': 'right',
                    'background-color': '#11479e'
                }
            },
            {
                selector: 'edge',
                style: {
                    'width': 2,
                    'target-arrow-shape': 'triangle',
                    'line-color': '#9dbaea',
                    'target-arrow-color': '#9dbaea',
                    'curve-style': 'unbundled-bezier'
                }
            }
        ]
    });
    // legend
    cy.add([
        {group: 'nodes', data: {id: 'end entity'}, position: { x: 500, y: 50 }, style: {'background-color': '#11479e'}},
        {group: 'nodes', data: {id: 'intermediate'}, position: { x: 500, y: 80 }, style: {'background-color': '#009600'}},
        {group: 'nodes', data: {id: 'root'}, position: { x: 500, y: 110 }, style: {'background-color': '#bd0000'}}
    ]);
    let current = json;
    let eles = cy.add({group: 'nodes', data: {id: formatCommonName(current.certificate.subject)}, position: { x: 50, y: 50 }});
    if (current.certificate.ca) {
        if (current.certificate.subject.cn === current.certificate.issuer.cn) {
            // this is a root CA, show it red
            eles.style({'background-color': '#bd0000'});
        } else {
            // intermediate, use green
            eles.style({'background-color': '#009600'});
        }
    }
    if (current.parents) {
        let y = 200;
        for (var i = 0; i < current.parents.length; i++) {
            y += 20;
            addParentToCertPaths(current, current.parents[i], i*100 + 70, y);
        }
    }
}

function getCertPaths(id) {
    let req = new Request('/api/v1/paths?id=' + id);
    return fetch(req)
        .then(function(response) {
            if (!response.ok) {
                logs.textContent = 'Error: ' + response.status + ' ' + response.statusText;
                logs.style.color = 'Red';
                throw 'Server error. Status: ' + response.status + ' ' + response.statusText;
            }
            return response.json().then(function(json) {
                document.getElementById('cy').textContent = '';
                drawCertPaths(json);
            });
        })
        .catch(function(err) {
            logs.textContent = 'Error when retrieving certificate paths: ' + err;
            logs.style.color = 'Red';
            throw 'Could not retrieve certificate paths: ' + err;
        });
}

function loadCert(id, sha256) {
    let req = new Request('/api/v1/certificate?id=' + id);
    if (sha256) {
        req = new Request('/api/v1/certificate?sha256=' + sha256);
    }
    return fetch(req)
        .then(function(response) {
            if (!response.ok) {
                logs.textContent = 'Error: ' + response.status + ' ' + response.statusText;
                logs.style.color = 'Red';
                throw 'Server error. Status: ' + response.status + ' ' + response.statusText;
            }
            return response.json().then(function(json) {
                setFieldsFromJSON(json);
                getCertPaths(json.id);
                logs.textContent = '';
            });
        })
        .catch(function(err) {
            logs.textContent = 'Error when loading certificate: ' + err;
            logs.style.color = 'Red';
            throw 'Could not load certificate: ' + err;
        });
}

function send(e) {
    e.preventDefault();
    document.getElementById('cy').innerHTML = '<img src="img/spinner.gif" />';
    logs.style.color = 'Blue';
    logs.textContent = 'Certificate posted, waiting for result...';

    var certificate = document.getElementById('certificate').value;
    certificate = certificate.trim();
    if (!certificate.startsWith('-----BEGIN CERTIFICATE-----') || !certificate.endsWith('-----END CERTIFICATE-----')) {
        console.log(certificate);
        let err = 'Invalid certificate format, must be PEM encoded';
        logs.textContent= 'Error: ' + err;
        logs.style.color = 'Red';
        throw err;
    }

    return postCertificate(certificate)
        .then(function(certJson) {
            setFieldsFromJSON(certJson);
            getCertPaths(certJson.id);
            logs.textContent = '';
        })
        .catch(function(err) {
            logs.textContent = 'Error: ' + err;
            logs.style.color = 'Red';
        });
}
