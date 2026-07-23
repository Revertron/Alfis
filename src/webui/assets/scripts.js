// ALFIS web UI scripts. Ported from the old webview UI: the
// external.invoke() bridge is replaced by fetch() calls to the JSON API and
// an EventSource stream of events from the node.

var recordsBuffer = [];
var ownerSigning = "";
var ownerEncryption = "";
var availableZones = [];
var myDomains = [];
var currentZone;
var currentDomain = "";
var currentSelectedKey = -1;
var keysLoaded = [];
var stateMining = false;
var eventSource = null;
var initialized = false;

document.addEventListener('click', function (event) {
    closeDropdowns();
});

// ------------------------------------------------------------------
// Transport
// ------------------------------------------------------------------

async function api(method, path, body) {
    var opts = { method: method, headers: {} };
    if (body !== undefined) {
        opts.headers['Content-Type'] = 'application/json';
        opts.body = JSON.stringify(body);
    }
    var response = await fetch(path, opts);
    if (response.status === 401) {
        showLogin();
        throw new Error('Unauthorized');
    }
    var data = {};
    try {
        data = await response.json();
    } catch (e) {
        // Empty or non-JSON body
    }
    if (!response.ok) {
        throw new Error(data.error || ('Request failed (' + response.status + ')'));
    }
    return data;
}

function onLoad() {
    api('GET', '/api/status')
        .then(function() { init(); })
        .catch(function() { /* 401 already showed the login dialog */ });
}

function init() {
    if (initialized) {
        return;
    }
    initialized = true;
    closeDialog('login_dialog');
    showMiningIndicator(false, false);
    refreshAll();
    loadEventsLog();
    connectEvents();
}

function refreshAll() {
    api('GET', '/api/status').then(function(status) {
        setStats(status.blocks, status.domains, status.keys, status.nodes);
        if (status.mining) {
            setLeftStatusBarText('Mining...');
            showMiningIndicator(true, false);
        } else if (status.syncing) {
            setLeftStatusBarText('Synchronizing ' + status.synced_blocks + '/' + status.sync_height);
            showMiningIndicator(true, true);
        } else if (status.nodes >= 3) {
            setLeftStatusBarText('Idle');
            showMiningIndicator(false, false);
        } else {
            setLeftStatusBarText('Connecting to ' + status.nodes + ' nodes...');
            showMiningIndicator(false, false);
        }
    }).catch(function() {});
    api('GET', '/api/zones').then(function(data) {
        availableZones = data.zones;
        refreshZonesList();
    }).catch(function() {});
    loadKeys();
    loadDomains();
}

function loadEventsLog() {
    api('GET', '/api/events/log').then(function(data) {
        document.getElementById("tab_events").innerHTML = "";
        data.events.forEach(function(e) {
            addEvent(e.severity, e.time, e.text);
        });
    }).catch(function() {});
}

function connectEvents() {
    if (eventSource !== null) {
        eventSource.close();
    }
    eventSource = new EventSource('/api/events');
    var firstOpen = true;
    eventSource.onopen = function() {
        if (!firstOpen) {
            // Reconnected after a gap: pull fresh state, we may have missed frames
            refreshAll();
            loadEventsLog();
        }
        firstOpen = false;
    };
    eventSource.onmessage = function(event) {
        handleFrame(JSON.parse(event.data));
    };
}

function handleFrame(frame) {
    switch (frame.type) {
        case 'status':
            setLeftStatusBarText(frame.text);
            showMiningIndicator(frame.busy, frame.blue);
            break;
        case 'stats':
            setStats(frame.blocks, frame.domains, frame.keys, frame.nodes);
            break;
        case 'event':
            addEvent(frame.severity, frame.time, frame.text);
            break;
        case 'toast':
            if (frame.severity === 'fail') {
                showError(frame.text);
            } else if (frame.severity === 'warn') {
                showWarning(frame.text);
            } else {
                showSuccess(frame.text);
            }
            break;
        case 'keys_changed':
            loadKeys();
            break;
        case 'domains_changed':
            loadDomains();
            break;
    }
}

// ------------------------------------------------------------------
// Login
// ------------------------------------------------------------------

function showLogin() {
    if (eventSource !== null) {
        eventSource.close();
        eventSource = null;
    }
    initialized = false;
    document.getElementById("login_dialog").className = "modal is-active";
    document.getElementById("login_password").focus();
}

function doLogin() {
    var password = document.getElementById("login_password").value;
    var error = document.getElementById("login_error");
    var button = document.getElementById("login_button");
    button.disabled = true;
    fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: password })
    }).then(function(response) {
        button.disabled = false;
        if (response.ok) {
            document.getElementById("login_password").value = "";
            error.className = "help is-danger is-hidden";
            init();
        } else {
            response.json().then(function(data) {
                error.textContent = data.error || "Wrong password";
            }).catch(function() {
                error.textContent = "Wrong password";
            });
            error.className = "help is-danger";
        }
    }).catch(function() {
        button.disabled = false;
        error.textContent = "Server is not reachable";
        error.className = "help is-danger";
    });
}

function logout() {
    api('POST', '/api/logout').catch(function() {}).then(function() {
        showLogin();
    });
}

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

function escapeHtml(text) {
    return String(text)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

// Fills {placeholder} slots in a template in a single pass, so '$' sequences
// in values are inserted literally and inserted values are never re-scanned
// for other placeholders.
function fill(template, map) {
    return template.replace(/\{\w+\}/g, function(match) {
        return (match in map) ? map[match] : match;
    });
}

function closeDropdowns(except) {
    var dropdowns = document.getElementsByClassName("dropdown is-active");
    for (var i = 0; i < dropdowns.length; i++) {
        if (dropdowns[i] != except) {
            dropdowns[i].classList.remove('is-active');
        }
    }
}

// ------------------------------------------------------------------
// Records
// ------------------------------------------------------------------

function addRecord(record) {
    recordsBuffer.push(record);
    refreshRecordsList();
}

function delRecord(index) {
    recordsBuffer.splice(index, 1);
    refreshRecordsList();
}

function refreshRecordsList() {
    let buf = "";
    if (recordsBuffer.length > 0) {
        buf = "<label class=\"label\">Records:</label>\n";
    }

    function makeRecord(value, index, array) {
        let data = value.addr;
        if (value.type === "MX") {
            data = value.priority + " " + value.host;
        } else if (value.type === "CNAME" || value.type === "NS") {
            data = value.host;
        } else if (value.type === "TXT" || value.type === "TLSA") {
            data = value.data.toString();
        } else if (value.type === "SRV") {
            data = value.priority + " " + value.weight + " " + value.port + " " + value.host;
        }

        const text = "<div class=\"field is-grouped\">" +
            "<input class=\"input\" type=\"text\" value=\"{1}\" readonly>" +
            "<input class=\"input ml-3 has-text-centered\" type=\"text\" size=\"6\" style=\"width: 20%;\" value=\"{2}\" readonly>" +
            "<input class=\"input ml-3 has-text-centered\" type=\"text\" size=\"6\" style=\"width: 20%;\" value=\"{3}\" readonly>" +
            "<input class=\"input ml-3\" type=\"text\" value='{4}' readonly>" +
            "<button class=\"button is-danger is-outlined ml-3\" id=\"record_delete\" onclick=\"delRecord({5});\">" +
            "  <span class=\"icon is-small\">" +
            "    <svg viewBox=\"0 0 24 24\" style=\"width: 20px; height: 20px;\"><path d=\"M22.54 16.88L20.41 19L22.54 21.12L21.12 22.54L19 20.41L16.88 22.54L15.47 21.12L17.59 19L15.47 16.88L16.88 15.47L19 17.59L21.12 15.46L22.54 16.88M12 13C10.9 13 10 13.9 10 15S10.9 17 12 17 14 16.1 14 15 13.1 13 12 13M13.35 21H5.5C4.58 21 3.81 20.38 3.58 19.54L1.04 10.27C1 10.18 1 10.09 1 10C1 9.45 1.45 9 2 9H6.79L11.17 2.45C11.36 2.16 11.68 2 12 2S12.64 2.16 12.83 2.44L17.21 9H22C22.55 9 23 9.45 23 10L22.97 10.27L22 13.81C21.43 13.5 20.79 13.24 20.12 13.11L20.7 11H3.31L5.5 19H13C13 19.7 13.13 20.37 13.35 21M9.2 9H14.8L12 4.8L9.2 9Z\"></path></svg>" +
            "  </span>" +
            "</button>" +
            "</div>";
        buf += fill(text, {
            "{1}": escapeHtml(value.domain),
            "{2}": escapeHtml(value.type),
            "{3}": escapeHtml(value.ttl),
            "{4}": escapeHtml(data),
            "{5}": String(index)
        });
    }

    recordsBuffer.forEach(makeRecord);
    document.getElementById("domain_records").innerHTML = buf;
}

function showNewRecordDialog() {
    var button_positive = document.getElementById("new_record_positive_button");
    button_positive.onclick = function() {
        checkRecord(getRecordFromDialog());
    };

    var button_negative = document.getElementById("new_record_negative_button");
    button_negative.onclick = function() {
        var dialog = document.getElementById("new_record_dialog");
        dialog.className = "modal";
        refreshRecordsList();
    }

    var dialog = document.getElementById("new_record_dialog");
    dialog.className = "modal is-active";
}

function getRecordFromDialog() {
    let record_priority;
    const record_name = document.getElementById("record_name").value.toLowerCase();
    const record_type = document.getElementById("record_type").value;
    const record_ttl = parseInt(document.getElementById("record_ttl").value);
    let record_data = document.getElementById("record_data").value;
    if (record_type == "CNAME" || record_type == "NS") {
        return { type: record_type, domain: record_name, ttl: record_ttl, host: record_data }
    } else if (record_type == "MX") {
        record_priority = parseInt(document.getElementById("record_priority").value);
        return { type: record_type, domain: record_name, ttl: record_ttl, priority: record_priority, host: record_data }
    }  else if (record_type == "TXT") {
        return { type: record_type, domain: record_name, ttl: record_ttl, data: record_data }
    } else if (record_type == "SRV") {
        record_priority = parseInt(document.getElementById("record_priority").value);
        const record_weight = parseInt(document.getElementById("record_weight").value);
        const record_port = parseInt(document.getElementById("record_port").value);
        return { type: record_type, domain: record_name, ttl: record_ttl, priority: record_priority, weight: record_weight, port: record_port, host: record_data }
    } else if (record_type == "TLSA") {
        const certificate_usage = parseInt(document.getElementById("record_priority").value);
        const selector = parseInt(document.getElementById("record_weight").value);
        const matching_type = parseInt(document.getElementById("record_port").value);
        record_data = hexToBytes(record_data);
        return { type: record_type, domain: record_name, ttl: record_ttl, certificate_usage: certificate_usage, selector: selector, matching_type: matching_type, data: record_data }
    }
    return { type: record_type, domain: record_name, ttl: record_ttl, addr: record_data }
}

function checkRecord(record) {
    api('POST', '/api/records/check', record).then(function(data) {
        recordOkay(data.ok);
    }).catch(function(e) {
        showWarning(e.message);
    });
}

function recordOkay(okay) {
    if (okay) {
        addRecord(getRecordFromDialog()); // It will refresh list
        var dialog = document.getElementById("new_record_dialog");
        dialog.className = "modal";
    } else {
        showWarning('Record is not valid!');
    }
}

// ------------------------------------------------------------------
// My domains
// ------------------------------------------------------------------

function loadDomains() {
    api('GET', '/api/domains').then(function(data) {
        myDomains = data.domains;
        refreshMyDomains();
    }).catch(function() {});
}

function formatDate(date) {
    var month = date.getMonth() + 1;
    if (month < 10) {
        month = "0" + month;
    }
    var day = date.getDate();
    if (day < 10) {
        day = "0" + day;
    }
    return "{y}-{m}-{d}".replace("{y}", date.getFullYear()).replace("{m}", month).replace("{d}", day);
}

function refreshMyDomains() {
    const row = '<tr class="is-clickable" onclick="editDomain(\'{domain}\', event);"><td class="has-text-weight-semibold">{title}</td><td class="w100"><div class="tags">{tags}</div></td><td>{date1}</td><td>{date2}</td></tr>';
    const tag = '<span class="tag" title="{ip}">{domain}</span>';
    let rows = "";
    myDomains.forEach(function(value, index, array) {
        const title = escapeHtml(value.name);
        const domain_data = value.data;
        const start = formatDate(new Date(value.timestamp * 1000));
        const expire = formatDate(new Date(value.expire * 1000));
        let tags = "";
        if (typeof domain_data.records !== 'undefined') {
            domain_data.records.forEach(function(v, i, a) {
                if (typeof v.domain !== 'undefined') {
                    let ip = "";
                    if (typeof v.addr !== 'undefined') {
                        ip = v.addr;
                    } else if (typeof v.host !== 'undefined') {
                        ip = v.host;
                    }
                    tags = tags + fill(tag, {"{domain}": escapeHtml(v.domain), "{ip}": escapeHtml(ip)});
                }
            });
        } else {
            tags = fill(tag, {"{domain}": "No records", "{ip}": ""});
        }
        rows = rows + fill(row, {"{title}": title, "{domain}": title, "{tags}": tags, "{date1}": start, "{date2}": expire});
    });
    document.getElementById("my_domains").innerHTML = rows;
    if (rows !== "") {
        document.getElementById("my_domains_table").style.display = 'table';
    } else {
        document.getElementById("my_domains_table").style.display = 'none';
    }
}

function editDomain(domain, event) {
    myDomains.forEach(function(value, index, array) {
        if (domain !== value.name) {
            return;
        }
        const title = value.name;
        const domain_data = value.data;
        recordsBuffer = [];
        if (typeof domain_data.records !== 'undefined') {
            domain_data.records.forEach(function(v, i, a) {
                recordsBuffer.push(v);
            });
        }
        currentDomain = title.replace("." + domain_data.zone, "");
        document.getElementById("new_domain").value = currentDomain;
        if (typeof domain_data.info !== 'undefined') {
            document.getElementById("info_text").value = domain_data.info;
        }
        if (typeof domain_data.contacts !== 'undefined') {
            let count = 1;
            domain_data.contacts.forEach(function(v, i, a) {
                document.getElementById("contact" + count + "_name").value = decodeURIComponent(v.name);
                document.getElementById("contact" + count + "_value").value = decodeURIComponent(v.value);
                count = count + 1;
            });
        }
        changeZone(domain_data.zone, event);
        refreshRecordsList();
        showNewDomainDialog();
    });
}

// ------------------------------------------------------------------
// Tabs and dialogs
// ------------------------------------------------------------------

function openTab(element, tabName) {
    var i, tabContent, tabLinks;

    tabContent = document.getElementsByClassName("tab row page");
    for (i = 0; i < tabContent.length; i++) {
        tabContent[i].className = "tab row page is-hidden";
    }

    tabLinks = document.getElementsByClassName("tab is-active");
    for (i = 0; i < tabLinks.length; i++) {
        tabLinks[i].className = "tab";
    }

    document.getElementById(tabName).className = "tab row page";
    element.parentElement.className = "tab is-active";
    refreshRecordsList();
}

function toggle(element, event) {
    event.stopPropagation();
    closeDropdowns(element);
    element.classList.toggle('is-active');
}

function showNewDomainDialog() {
    document.getElementById("new_domain_dialog").className = "modal is-active";
}

function closeDialog(name) {
    document.getElementById(name).className = "modal";
}

// ------------------------------------------------------------------
// Keys
// ------------------------------------------------------------------

function loadKeys() {
    api('GET', '/api/keys').then(function(data) {
        keysLoaded = data.keys;
        currentSelectedKey = data.keys.length > 0 ? data.active : -1;
        refreshKeysMenu();
        var public_key_field = document.getElementById("public_key");
        if (currentSelectedKey >= 0) {
            var active = keysLoaded[currentSelectedKey];
            public_key_field.value = active.public;
            public_key_field.title = active.file_name + "\n" + active.hash;
            document.getElementById("new_domain").disabled = false;
        } else {
            public_key_field.value = "";
            public_key_field.title = "";
        }
    }).catch(function() {});
}

function showNewKeyDialog() {
    document.getElementById("new_key_dialog").className = "modal is-active";
    document.getElementById("new_key_filename").focus();
}

function createKey() {
    var filename = document.getElementById("new_key_filename").value;
    api('POST', '/api/keys/create', { filename: filename }).then(function() {
        closeDialog('new_key_dialog');
        document.getElementById("new_key_button").disabled = true;
    }).catch(function(e) {
        showWarning(e.message);
    });
}

function refreshKeysMenu() {
    var buf = "";
    keysLoaded.forEach(function(value, index, array) {
        var file_name = value.file_name;
        if (file_name == "") {
            file_name = "[Not saved]";
        }

        var add_class = "";
        if (currentSelectedKey == index) {
            add_class = "is-active";
        }
        buf += fill("<a id=\"key-{id}\" class=\"dropdown-item {class}\" onclick=\"selectKey({index}, event);\" title=\"{title}\">{name}</a>", {
            "{id}": String(index),
            "{index}": String(index),
            "{class}": add_class,
            "{title}": escapeHtml(value.public),
            "{name}": escapeHtml(file_name)
        });
    });
    var links = document.getElementById("keys_links");
    links.innerHTML = buf;
    var cur_name = document.getElementById("keys_current_name");
    if (currentSelectedKey >= 0) {
        if (keysLoaded[currentSelectedKey].file_name == "") {
            cur_name.innerHTML = "[Not saved]";
        } else {
            cur_name.textContent = keysLoaded[currentSelectedKey].file_name;
        }
    } else {
        cur_name.textContent = "No keys";
    }
}

function selectKey(index, event) {
    event.stopPropagation();
    closeDropdowns();
    if (currentSelectedKey != index) {
        api('POST', '/api/keys/select', { index: parseInt(index) }).then(function() {
            keySelected(index);
        }).catch(function(e) {
            showWarning(e.message);
        });
    }
}

function keySelected(index) {
    currentSelectedKey = index;
    refreshKeysMenu();
}

// ------------------------------------------------------------------
// Domain mining
// ------------------------------------------------------------------

function createDomain() {
    if (typeof currentZone == 'undefined') {
        showWarning("Select a domain zone first");
        return;
    }
    var new_domain = document.getElementById("new_domain").value.toLowerCase();
    var domain = new_domain + "." + currentZone.name;
    var data = {};
    data.encrypted = "";
    data.zone = currentZone.name;
    data.info = document.getElementById("info_text").value;
    data.records = recordsBuffer;
    data.contacts = getContacts();
    var renewal = document.getElementById("renewal").checked;
    api('POST', '/api/domains', { name: domain, data: data, signing: ownerSigning, encryption: ownerEncryption, renewal: renewal }).then(function() {
        domainMiningStarted();
    }).catch(function(e) {
        showWarning(e.message);
        domainMiningUnavailable();
    });
}

function getContacts() {
    var result = [];
    for (var x = 1; x <= 3; x++) {
        var name = document.getElementById("contact" + x + "_name").value;
        var value = document.getElementById("contact" + x + "_value").value;
        if (name == "" || value == "") {
            continue;
        }
        var obj = {};
        obj.name = encodeURIComponent(name.trim());
        obj.value = encodeURIComponent(value.trim());
        result.push(obj);
    }
    return result;
}

function domainMiningStarted() {
    document.getElementById("new_domain_dialog").className = "modal";
    document.getElementById("add_record_button").disabled = true;
    document.getElementById("new_domain_button").disabled = true;
    document.getElementById("new_key_button").disabled = true;
}

function domainMiningUnavailable() {
    document.getElementById("new_domain_dialog").className = "modal";
    document.getElementById("add_record_button").disabled = false;
    document.getElementById("new_domain_button").disabled = false;
    document.getElementById("new_key_button").disabled = false;
}

function onDomainChange(element) {
    currentDomain = element.value;
    if (typeof currentZone !== 'undefined') {
        checkDomain(currentDomain + "." + currentZone.name);
    }
}

function checkDomain(domain) {
    api('GET', '/api/domains/check?name=' + encodeURIComponent(domain)).then(function(data) {
        domainAvailable(data.available);
    }).catch(function() {});
}

function domainAvailable(available) {
    var input = document.getElementById("new_domain");
    var button = document.getElementById("new_domain_button");
    var button2 = document.getElementById("add_record_button");
    if (available) {
        input.className = "input";
        button.disabled = false
        button2.disabled = false
    } else {
        input.className = "input is-danger";
        button.disabled = true
        button2.disabled = true
    }
}

// ------------------------------------------------------------------
// Modal dialogs (owner, contacts, info, confirm)
// ------------------------------------------------------------------

function showModalDialog(text, callback) {
    var message = document.getElementById("modal_text");
    message.textContent = text;

    var button_positive = document.getElementById("modal_positive_button");
    button_positive.onclick = function() {
        callback();
        dialog = document.getElementById("modal_dialog");
        dialog.className = "modal";
    };

    var button_negative = document.getElementById("modal_negative_button");
    button_negative.onclick = function() {
        dialog = document.getElementById("modal_dialog");
        dialog.className = "modal";
    }

    var dialog = document.getElementById("modal_dialog");
    dialog.className = "modal is-active";
}

function showOwnerDialog() {
    var dialog = document.getElementById("owner_dialog");
    dialog.className = "modal is-active";
}

function isValidOwner(text) {
    if (text.length != 64) {
        return false;
    }
    var regexp = /^[0-9A-F]{64}$/i;
    return regexp.test(text);
}

function ownerPositiveButton() {
    var signing = document.getElementById("owner_signing").value;
    var encryption = document.getElementById("owner_encryption").value;
    if (signing != "" && encryption != "") {
        if (isValidOwner(signing) && isValidOwner(encryption)) {
            ownerSigning = signing;
            ownerEncryption = encryption;
        } else {
            showWarning("Wrong owner keys!");
            return;
        }
    } else {
        ownerSigning = "";
        ownerEncryption = "";
    }
    var dialog = document.getElementById("owner_dialog");
    dialog.className = "modal";
}

function ownerCancelButton() {
    var dialog = document.getElementById("owner_dialog");
    dialog.className = "modal";
}

function showContactsDialog() {
    var dialog = document.getElementById("contacts_dialog");
    dialog.className = "modal is-active";
}

function contactsPositiveButton() {
    var dialog = document.getElementById("contacts_dialog");
    dialog.className = "modal";
}

function contactsNegativeButton() {
    var dialog = document.getElementById("contacts_dialog");
    dialog.className = "modal";
}

function showDomainInfoDialog() {
    var dialog = document.getElementById("info_dialog");
    dialog.className = "modal is-active";
}

function infoPositiveButton() {
    var dialog = document.getElementById("info_dialog");
    dialog.className = "modal";
}

function infoNegativeButton() {
    var dialog = document.getElementById("info_dialog");
    dialog.className = "modal";
}

// ------------------------------------------------------------------
// Notifications
// ------------------------------------------------------------------

function showWarning(text) {
    var warning = document.getElementById("notification_warning");
    var message = document.getElementById("warning_text");
    message.textContent = text;

    warning.className = "notification mini is-warning";
    var button = document.getElementById("warning_close");
    button.onclick = function() {
        message.value = "";
        warning.className = "notification mini is-warning is-hidden";
    }
    setTimeout(button.onclick, 5000);
}

function showError(text) {
    var warning = document.getElementById("notification_error");
    var message = document.getElementById("error_text");
    message.textContent = text;

    warning.className = "notification mini is-danger";
    var button = document.getElementById("error_close");
    button.onclick = function() {
        message.value = "";
        warning.className = "notification mini is-danger is-hidden";
    }
}

function showSuccess(text) {
    var warning = document.getElementById("notification_success");
    var message = document.getElementById("success_text");
    message.textContent = text;

    warning.className = "notification mini is-success";
    var button = document.getElementById("success_close");
    button.onclick = function() {
        message.value = "";
        warning.className = "notification mini is-success is-hidden";
    }
}

// ------------------------------------------------------------------
// Status bar
// ------------------------------------------------------------------

function showMiningIndicator(visible, blue) {
    var indicator = document.getElementById("busy_indicator");
    var parent = document.getElementById("indicator_parent");
    var add = "";
    stateMining = true;
    if (blue) {
        add = " busy_blue";
        stateMining = false;
    }
    if (visible) {
        indicator.className = 'busy_indicator' + add;
        parent.style.display = 'flex';
    } else {
        indicator.className = 'busy_indicator is-hidden';
        parent.style.display = 'none';
        stateMining = false;
        document.getElementById("add_record_button").disabled = false;
        document.getElementById("new_domain_button").disabled = false;
        document.getElementById("new_key_button").disabled = false;
    }
}

function miningIndicatorClick(element) {
    if (stateMining) {
        showModalDialog("Do you really want to stop mining?", function() {
            api('POST', '/api/mining/stop').catch(function() {});
        });
    }
}

function setLeftStatusBarText(text) {
    var bar = document.getElementById("status_bar_left");
    bar.textContent = text;
}

function setStats(blocks, domains, keys, nodes) {
    document.getElementById("stat_blocks").textContent = blocks;
    document.getElementById("stat_domains").textContent = domains;
    document.getElementById("stat_keys").textContent = keys;
    document.getElementById("stat_nodes").textContent = nodes;
}

function addEvent(type, time, message) {
    var t = "";
    if (type == 'warn') {
        t = "is-warning";
    } else if (type == 'fail') {
        t = "is-danger";
    } else if (type == 'luck') {
        t = "is-success";
    }

    var html = "<article class=\"message mb-1 {type}\"><div class=\"message-body px-2 py-1\">{time}&nbsp;&nbsp;<strong>{text}</strong></div></article>";
    var buf = fill(html, {"{type}": t, "{time}": escapeHtml(time), "{text}": escapeHtml(message)});
    var tab_events = document.getElementById("tab_events");
    tab_events.innerHTML = tab_events.innerHTML + buf;
}

// ------------------------------------------------------------------
// Zones
// ------------------------------------------------------------------

function refreshZonesList() {
    var buf = "";
    availableZones.sort(function compare(rhs, lhs) {
        if (rhs.name < lhs.name) {
            return -1;
        } else if (rhs.name > lhs.name) {
            return 1;
        } else {
            return 0;
        }
    });

    availableZones.forEach(function(value, index, array) {
        var note = "";
        if (value.yggdrasil) {
            note = "*";
        }
        var zone = value.name + note;
        var add_class = "";
        if (typeof currentZone !== 'undefined' && currentZone.name == value.name) {
            add_class = "is-active";
        }
        buf += fill("<a id=\"zone-{1}\" class=\"dropdown-item {2}\" onclick=\"changeZone('{3}', event);\">.{4}</a>", {
            "{1}": escapeHtml(value.name),
            "{2}": add_class,
            "{3}": escapeHtml(value.name),
            "{4}": escapeHtml(zone)
        });
    });
    var links = document.getElementById("zones-links");
    links.innerHTML = buf;
    if (typeof currentZone !== 'undefined') {
        var cur_name = document.getElementById("zones-current-name");
        var name = "." + currentZone.name;
        if (currentZone.yggdrasil) {
            name = name + "*";
        }
        cur_name.textContent = name;
    }
}

function changeZone(zone, event) {
    if (event) {
        event.stopPropagation();
    }
    closeDropdowns();
    availableZones.forEach(function(value, index, array) {
        if (value.name == zone) {
            currentZone = value;
            checkDomain(currentDomain + "." + currentZone.name);
        }
    });
    refreshZonesList();
}

// Convert a hex string to a byte array
function hexToBytes(hex) {
    for (var bytes = [], c = 0; c < hex.length; c += 2) {
        bytes.push(parseInt(hex.substr(c, 2), 16));
    }
    return bytes;
}
