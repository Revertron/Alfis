var recordsBuffer = [];

function addRecord(record) {
    recordsBuffer.push(record);
    refresh_records_list();
}

function delRecord(index) {
    recordsBuffer.splice(index, 1);
    refresh_records_list();
}

function refresh_records_list() {
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
        } else if (value.type == "CNAME") {
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
               "  <span class=\"icon is-small\"><i class=\"fas fa-times\"></i></span>" +
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
        checkRecord(get_record_from_dialog());
    };

    var button_negative = document.getElementById("new_record_negative_button");
    button_negative.onclick = function() {
        var dialog = document.getElementById("new_record_dialog");
        dialog.className = "modal";
        refresh_records_list();
    }

    var dialog = document.getElementById("new_record_dialog");
    dialog.className = "modal is-active";
}

function get_record_from_dialog() {
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
    }
    return { type: record_type, domain: record_name, ttl: record_ttl, addr: record_data }
}

function onLoad() {
    external.invoke(JSON.stringify({cmd: 'loaded'}));
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
        addRecord(get_record_from_dialog()); // It will refresh list
        var dialog = document.getElementById("new_record_dialog");
        dialog.className = "modal";
    } else {
        showWarning('Record is not valid!');
    }
}

function createDomain() {
    var new_domain = document.getElementById("new_domain").value.toLowerCase();
    var new_dom_records = JSON.stringify(recordsBuffer);
    external.invoke(JSON.stringify({cmd: 'mineDomain', name: new_domain, records: new_dom_records}));
}

function domainMiningStarted() {
    recordsBuffer = [];
}

function createZone() {
    var new_zone = document.getElementById("new_zone").value;
    var difficulty = document.getElementById("new_zone_difficulty").value;
    obj = {};
    obj.name = new_zone;
    obj.difficulty = parseInt(difficulty);
    data = JSON.stringify(obj);
    external.invoke(JSON.stringify({cmd: 'mineZone', name: new_zone, data: data}));
}

function sendAction(param) {
    external.invoke(JSON.stringify(param));
}

function onDomainChange(element) {
    external.invoke(JSON.stringify({cmd: 'checkDomain', name: element.value}));
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

function onZoneChange() {
    var button = document.getElementById("new_zone_button");
    var diff = document.getElementById("new_zone_difficulty");
    d = parseInt(diff.value);
    // Checking for NaN first
    if (d != d || d < 20 || d > 50) {
        button.disabled = true;
        diff.className = "input is-danger";
    } else {
        diff.className = "input";
        var input = document.getElementById("new_zone");
        external.invoke(JSON.stringify({cmd: 'checkZone', name: input.value}));
    }
}

function zoneAvailable(available) {
    var input = document.getElementById("new_zone");
    var button = document.getElementById("new_zone_button");
    if (available) {
        input.className = "input";
        button.disabled = false;
        var diff = document.getElementById("new_zone_difficulty");
        d = parseInt(diff.value);
        // Checking for NaN first
        if (d != d || d < 20 || d > 50) {
            button.disabled = true;
            diff.className = "input is-danger";
        }
    } else {
        input.className = "input is-danger";
        button.disabled = true;
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

function showWarning(text) {
    var warning = document.getElementById("notification_warning");
    var message = document.getElementById("warning_text");
    message.innerHTML = text;

    warning.className = "notification is-warning";
    var button = document.getElementById("warning_close");
    button.onclick = function() {
        message.value = "";
        warning.className = "notification is-warning is-hidden";
    }
    setTimeout(button.onclick, 5000);
}

function showSuccess(text) {
    var warning = document.getElementById("notification_success");
    var message = document.getElementById("success_text");
    message.innerHTML = text;

    warning.className = "notification is-success";
    var button = document.getElementById("success_close");
    button.onclick = function() {
        message.value = "";
        warning.className = "notification is-success is-hidden";
    }
}

function showMiningIndicator(visible, blue) {
    var indicator = document.getElementById("busy_indicator");
    var parent = document.getElementById("indicator_parent");
    var add = "";
    if (blue) {
        add = " busy_blue";
    }
    if (visible) {
        indicator.className = 'busy_indicator' + add;
        parent.style.display = 'flex';
    } else {
        indicator.className = 'busy_indicator is-hidden';
        parent.style.display = 'none';
    }
}

function miningIndicatorClick(element) {
    showModalDialog("Do you really want to stop mining?", function() {
        external.invoke(JSON.stringify({cmd: 'stopMining'}));
    });
}

function setLeftStatusBarText(text) {
    var bar = document.getElementById("status_bar_left");
    bar.innerHTML = text;
}

function setRightStatusBarText(text) {
    var bar = document.getElementById("status_bar_right");
    bar.innerHTML = text;
}

function keystoreChanged(path, pub_key, hash) {
    if (path == '') {
        path = "In memory";
    }
    var public_key_hash = document.getElementById("public_key_hash");
    public_key_hash.value = hash;

    var save_key = document.getElementById("save_key");
    save_key.disabled = false;

    var new_domain = document.getElementById("new_domain");
    new_domain.disabled = false;

    var new_zone = document.getElementById("new_zone");
    new_zone.disabled = false;
    var new_zone_difficulty = document.getElementById("new_zone_difficulty");
    new_zone_difficulty.disabled = false;
}