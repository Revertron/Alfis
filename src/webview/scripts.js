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

document.addEventListener('click', function (event) {
    closeDropdowns();
});

function closeDropdowns(except) {
    // Get all elements with class="dropdowns" and hide them
    var dropdowns = document.getElementsByClassName("dropdown is-active");
    for (i = 0; i < dropdowns.length; i++) {
        if (dropdowns[i] != except) {
            dropdowns[i].classList.remove('is-active');
        }
    }
}

function addRecord(record) {
    recordsBuffer.push(record);
    refreshRecordsList();
}

function delRecord(index) {
    recordsBuffer.splice(index, 1);
    refreshRecordsList();
}

function refreshRecordsList() {
    var buf = "";
    if (recordsBuffer.length > 0) {
        buf = "<label class=\"label\">Records:</label>\n";
    }
    function getInput(text) {
        if (typeof text === "string"){
            // TODO sanitize
        }
        return '<input class="input" type="text" value="' + text + '" readonly>';
    }

    function makeRecord(value, index, array) {
        var data = value.addr;
        if (value.type == "MX") {
            data = value.priority + " " + value.host;
        } else if (value.type == "CNAME" || value.type == "NS") {
            data = value.host;
        } else if (value.type == "TXT") {
            data = value.data;
        } else if (value.type == "SRV") {
            data = value.priority + " " + value.weight + " " + value.port + " " + value.host;
        }

        var text = "<div class=\"field is-grouped\">" +
               "<input class=\"input\" type=\"text\" value=\"{1}\" readonly>" +
               "<input class=\"input ml-3 has-text-centered\" type=\"text\" size=\"6\" style=\"width: 20%;\" value=\"{2}\" readonly>" +
               "<input class=\"input ml-3 has-text-centered\" type=\"text\" size=\"6\" style=\"width: 20%;\" value=\"{3}\" readonly>" +
               "<input class=\"input ml-3\" type=\"text\" value=\"{4}\" readonly>" +
               "<button class=\"button is-danger is-outlined ml-3\" id=\"record_delete\" onclick=\"delRecord({5});\">" +
               "  <span class=\"icon is-small\">" +
               "    <svg viewBox=\"0 0 24 24\" style=\"width: 20px; height: 20px;\"><path d=\"M22.54 16.88L20.41 19L22.54 21.12L21.12 22.54L19 20.41L16.88 22.54L15.47 21.12L17.59 19L15.47 16.88L16.88 15.47L19 17.59L21.12 15.46L22.54 16.88M12 13C10.9 13 10 13.9 10 15S10.9 17 12 17 14 16.1 14 15 13.1 13 12 13M13.35 21H5.5C4.58 21 3.81 20.38 3.58 19.54L1.04 10.27C1 10.18 1 10.09 1 10C1 9.45 1.45 9 2 9H6.79L11.17 2.45C11.36 2.16 11.68 2 12 2S12.64 2.16 12.83 2.44L17.21 9H22C22.55 9 23 9.45 23 10L22.97 10.27L22 13.81C21.43 13.5 20.79 13.24 20.12 13.11L20.7 11H3.31L5.5 19H13C13 19.7 13.13 20.37 13.35 21M9.2 9H14.8L12 4.8L9.2 9Z\"></path></svg>" +
               "  </span>" +
               "</button>" +
               "</div>";
        buf += text.replace("{1}", value.domain)
                   .replace("{2}", value.type)
                   .replace("{3}", value.ttl)
                   .replace("{4}", data)
                   .replace("{5}", index);
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
    var record_name = document.getElementById("record_name").value.toLowerCase();
    var record_type = document.getElementById("record_type").value;
    var record_ttl = parseInt(document.getElementById("record_ttl").value);
    var record_data = document.getElementById("record_data").value;
    if (record_type == "CNAME" || record_type == "NS") {
        return { type: record_type, domain: record_name, ttl: record_ttl, host: record_data }
    } else if (record_type == "MX") {
        var record_priority = parseInt(document.getElementById("record_priority").value);
        return { type: record_type, domain: record_name, ttl: record_ttl, priority: record_priority, host: record_data }
    }  else if (record_type == "TXT") {
        return { type: record_type, domain: record_name, ttl: record_ttl, data: record_data }
    } else if (record_type == "SRV") {
        var record_priority = parseInt(document.getElementById("record_priority").value);
        var record_weight = parseInt(document.getElementById("record_weight").value);
        var record_port = parseInt(document.getElementById("record_port").value);
        return { type: record_type, domain: record_name, ttl: record_ttl, priority: record_priority, weight: record_weight, port: record_port, host: record_data }
    } else if (record_type == "TLSA") {
        var certificate_usage = parseInt(document.getElementById("record_priority").value);
        var selector = parseInt(document.getElementById("record_weight").value);
        var matching_type = parseInt(document.getElementById("record_port").value);
        record_data = hexToBytes(record_data);
        return { type: record_type, domain: record_name, ttl: record_ttl, certificate_usage: certificate_usage, selector: selector, matching_type: matching_type, data: record_data }
    }
    return { type: record_type, domain: record_name, ttl: record_ttl, addr: record_data }
}

function clearMyDomains() {
    myDomains = [];
}

function addMyDomain(name, timestamp, expire, data) {
    myDomains.push({name: name, timestamp: timestamp, expire: expire, data: data});
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
    var row = '<tr class="is-clickable" onclick="editDomain(\'{domain}\', event);"><td class="has-text-weight-semibold">{title}</td><td class="w100"><div class="tags">{tags}</div></td><td>{date1}</td><td>{date2}</td></tr>';
    var tag = '<span class="tag" title="{ip}">{domain}</span>';
    var rows = "";
    myDomains.forEach(function(value, index, array) {
        var title = value.name;
        var domain_data = JSON.parse(value.data);
        var start = formatDate(new Date(value.timestamp * 1000));
        var expire = formatDate(new Date(value.expire * 1000));
        var tags = "";
        if (typeof domain_data.records !== 'undefined') {
            domain_data.records.forEach(function(v, i, a) {
                if (typeof v.domain !== 'undefined') {
                    var buf = tag.replace("{domain}", v.domain);
                    if (typeof v.addr !== 'undefined') {
                        buf = buf.replace("{ip}", v.addr);
                    } else if (typeof v.host !== 'undefined') {
                        buf = buf.replace("{ip}", v.host);
                    }
                    tags = tags + buf;
                }
            });
        } else {
            tags = tag.replace("{domain}", "No records").replace("{ip}", "");
        }
        rows = rows + row.replace("{title}", title).replace("{domain}", title).replace("{tags}", tags).replace("{date1}", start).replace("{date2}", expire);
    });
    document.getElementById("my_domains").innerHTML = rows;
    if (rows != "") {
        document.getElementById("my_domains_table").style.display = 'table';
    } else {
        document.getElementById("my_domains_table").style.display = 'none';
    }
}

function editDomain(domain, event) {
    myDomains.forEach(function(value, index, array) {
        if (domain != value.name) {
            return;
        }
        var title = value.name;
        var domain_data = JSON.parse(value.data);
        recordsBuffer = [];
        if (typeof domain_data.records !== 'undefined') {
            domain_data.records.forEach(function(v, i, a) {
                recordsBuffer.push(v);
            });
        }
        document.getElementById("new_domain").value = title.replace("." + domain_data.zone, "");
        if (typeof domain_data.info !== 'undefined') {
            document.getElementById("info_text").value = domain_data.info;
        }
        if (typeof domain_data.contacts !== 'undefined') {
            var count = 1;
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

function onLoad() {
    // Workaround for Arch Linux Webkit
    // https://github.com/Boscop/web-view/issues/212#issuecomment-671055663
    if (typeof window.external == 'undefined' || typeof window.external.invoke == 'undefined') {
        window.external = {
            invoke: function(x) {
                window.webkit.messageHandlers.external.postMessage(x);
            }
        };
    }

    external.invoke(JSON.stringify({cmd: 'loaded'}));
}

function openTab(element, tabName) {
    // Declare all variables
    var i, tabContent, tabLinks;

    // Get all elements with class="content" and hide them
    tabContent = document.getElementsByClassName("tab row page");
    for (i = 0; i < tabContent.length; i++) {
        tabContent[i].className = "tab row page is-hidden";
    }

    // Get all elements with class="tab" and remove the class "is-active"
    tabLinks = document.getElementsByClassName("tab is-active");
    for (i = 0; i < tabLinks.length; i++) {
        tabLinks[i].className = "tab";
    }

    // Show the current tab, and add an "is-active" class to the button that opened the tab
    document.getElementById(tabName).className = "tab row page";
    element.parentElement.className = "tab is-active";
    refreshRecordsList();
}

function toggle(element, event) {
    event.stopPropagation();
    closeDropdowns(element);
    element.classList.toggle('is-active');
}

function open_link(link) {
    external.invoke(JSON.stringify({cmd: 'open', link: link}));
}

function loadKey() {
    external.invoke(JSON.stringify({cmd: 'loadKey'}));
}

function createKey() {
    external.invoke(JSON.stringify({cmd: 'createKey'}));
}

function saveKey() {
    external.invoke(JSON.stringify({cmd: 'saveKey'}));
}

function checkRecord(data) {
    external.invoke(JSON.stringify({cmd: 'checkRecord', data: JSON.stringify(data)}));
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

function showNewDomainDialog() {
    document.getElementById("new_domain_dialog").className = "modal is-active";
}

function closeDialog(name) {
    document.getElementById(name).className = "modal";
}

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
    data = JSON.stringify(data);
    external.invoke(JSON.stringify({cmd: 'mineDomain', name: domain, data: data, signing: ownerSigning, encryption: ownerEncryption, renewal: renewal}));
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
    //recordsBuffer = [];
    //refreshRecordsList();
    document.getElementById("new_domain_dialog").className = "modal";
    document.getElementById("tab_domains").disabled = true;
    document.getElementById("domain_records").disabled = true;
    document.getElementById("add_record_button").disabled = true;
    document.getElementById("new_domain_button").disabled = true;
    document.getElementById("new_key_button").disabled = true;
}

function domainMiningUnavailable() {
    //recordsBuffer = [];
    //refreshRecordsList();
    document.getElementById("new_domain_dialog").className = "modal";
    document.getElementById("tab_domains").disabled = false;
    document.getElementById("domain_records").disabled = false;
    document.getElementById("add_record_button").disabled = false;
    document.getElementById("new_domain_button").disabled = false;
    document.getElementById("new_key_button").disabled = false;
}

function sendAction(param) {
    external.invoke(JSON.stringify(param));
}

function onDomainChange(element) {
    currentDomain = element.value;
    if (typeof currentZone !== 'undefined') {
        var domain = currentDomain + "." + currentZone.name;
        external.invoke(JSON.stringify({cmd: 'checkDomain', name: domain}));
    }
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
            alert("Wrong owner '{}'!".replace("{}", value));
            wrong = true;
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

function showWarning(text) {
    var warning = document.getElementById("notification_warning");
    var message = document.getElementById("warning_text");
    message.innerHTML = text;

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
    message.innerHTML = text;

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
    message.innerHTML = text;

    warning.className = "notification mini is-success";
    var button = document.getElementById("success_close");
    button.onclick = function() {
        message.value = "";
        warning.className = "notification mini is-success is-hidden";
    }
}

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
        document.getElementById("tab_domains").disabled = false;
        document.getElementById("domain_records").disabled = false;
        document.getElementById("add_record_button").disabled = false;
        document.getElementById("new_domain_button").disabled = false;
        document.getElementById("new_key_button").disabled = false;
    }
}

function miningIndicatorClick(element) {
    if (stateMining) {
        showModalDialog("Do you really want to stop mining?", function() {
            external.invoke(JSON.stringify({cmd: 'stopMining'}));
        });
    }
}

function setLeftStatusBarText(text) {
    var bar = document.getElementById("status_bar_left");
    bar.innerHTML = text;
}

function setStats(blocks, domains, keys, nodes) {
    document.getElementById("stat_blocks").innerHTML = blocks;
    document.getElementById("stat_domains").innerHTML = domains;
    document.getElementById("stat_keys").innerHTML = keys;
    document.getElementById("stat_nodes").innerHTML = nodes;
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
    var buf = html.replace("{type}", t).replace("{time}", time).replace("{text}", message);
    var tab_events = document.getElementById("tab_events");
    tab_events.innerHTML = tab_events.innerHTML + buf;
}

function keystoreChanged(path, pub_key, hash) {
    if (path == '') {
        path = "In memory";
    }
    var public_key_field = document.getElementById("public_key");
    public_key_field.value = pub_key;
    public_key_field.title = path + "\n" + hash;

    var save_key = document.getElementById("save_key").disabled = false;
    var new_domain = document.getElementById("new_domain").disabled = false;
}

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
        buf += "<a id=\"zone-{1}\" class=\"dropdown-item {2}\" onclick=\"changeZone('{3}', event);\">.{4}</a>"
            .replace("{1}", value.name)
            .replace("{2}", add_class)
            .replace("{3}", value.name)
            .replace("{4}", zone);
    });
    var links = document.getElementById("zones-links");
    links.innerHTML = buf;
    if (typeof currentZone !== 'undefined') {
        var cur_name = document.getElementById("zones-current-name");
        var name = "." + currentZone.name;
        if (currentZone.yggdrasil) {
            name = name + "*";
        }
        cur_name.innerHTML = name;
    }
}

function zonesChanged(text) {
    availableZones = JSON.parse(text);
    refreshZonesList();
}

function changeZone(zone, event) {
    event.stopPropagation();
    closeDropdowns();
    availableZones.forEach(function(value, index, array) {
        if (value.name == zone) {
            currentZone = value;
            var domain = currentDomain + "." + currentZone.name;
            external.invoke(JSON.stringify({cmd: 'checkDomain', name: domain}));
        }
    });
    refreshZonesList();
}

function refreshKeysMenu() {
    var buf = "";
    keysLoaded.forEach(function(value, index, array) {
        var file_name = value.file_name;
        if (file_name == "") {
            file_name = "[Not saved]";
        }
        var public = value.public;

        var add_class = "";
        if (currentSelectedKey == index) {
            add_class = "is-active";
        }
        buf += "<a id=\"key-{id}\" class=\"dropdown-item {class}\" onclick=\"selectKey({index}, event);\" title=\"{title}\">{name}</a>"
            .replace("{id}", index)
            .replace("{index}", index)
            .replace("{class}", add_class)
            .replace("{title}", public)
            .replace("{name}", file_name);
    });
    var links = document.getElementById("keys_links");
    links.innerHTML = buf;
    if (currentSelectedKey >= 0) {
        var cur_name = document.getElementById("keys_current_name");
        if (keysLoaded[currentSelectedKey].file_name == "") {
            cur_name.innerHTML = "[Not saved]";
        } else {
            cur_name.innerHTML = keysLoaded[currentSelectedKey].file_name;
        }
    }
}

function keysChanged(json) {
    keysLoaded = JSON.parse(json);
    refreshKeysMenu();
}

function selectKey(index, event) {
    event.stopPropagation();
    closeDropdowns();
    if (currentSelectedKey != index) {
        external.invoke(JSON.stringify({cmd: 'selectKey', index: parseInt(index)}));
    }
}

function keySelected(index) {
    currentSelectedKey = index;
    refreshKeysMenu();
}

// Convert a hex string to a byte array
function hexToBytes(hex) {
    for (var bytes = [], c = 0; c < hex.length; c += 2) {
        bytes.push(parseInt(hex.substr(c, 2), 16));
    }
    return bytes;
}