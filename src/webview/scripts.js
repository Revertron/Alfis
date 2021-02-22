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
        return '<input class="input" type="text" value="' + text + '" readonly>';
    }

    function makeRecord(value, index, array) {
        data = value.addr;
        if (value.type == "MX") {
            data = value.priority + " " + value.host;
        } else if (value.type == "CNAME") {
            data = value.host;
        } else if (value.type == "TXT") {
            data = value.data;
        } else if (value.type == "SRV") {
            data = value.priority + " " + value.weight + " " + value.port + " " + value.host;
        }

        buf += "<div class=\"columns is-1\">\n";
        buf += "<div class=\"column\">" + getInput(value.domain) + "</div>\n";
        buf += "<div class=\"column is-2\">" + getInput(value.type) + "</div>\n";
        buf += "<div class=\"column is-2\">" + getInput(value.ttl) + "</div>\n";
        buf += "<div class=\"column\">" + getInput(data) + "</div>\n";
        buf += "<div class=\"column is-1 align-right\">\n<button class=\"button is-danger is-outlined\" id=\"record_delete\" onclick=\"delRecord(" + index + ");\">";
        buf += "<span class=\"icon is-small\"><i class=\"fas fa-times\"></i></span></button></div>\n";
        buf += "</div>";
    }

    recordsBuffer.forEach(makeRecord);
    document.getElementById("domain_records").innerHTML = buf;
}

function showNewRecordDialog() {
    button_positive = document.getElementById("new_record_positive_button");
    button_positive.onclick = function() {
        addRecord(get_record_from_dialog()); // It will refresh list
        dialog = document.getElementById("new_record_dialog");
        dialog.className = "modal";
    };

    button_negative = document.getElementById("new_record_negative_button");
    button_negative.onclick = function() {
        dialog = document.getElementById("new_record_dialog");
        dialog.className = "modal";
        refresh_records_list();
    }

    dialog = document.getElementById("new_record_dialog");
    dialog.className = "modal is-active";
}

function get_record_from_dialog() {
    record_name = document.getElementById("record_name").value;
    record_type = document.getElementById("record_type").value;
    record_ttl = parseInt(document.getElementById("record_ttl").value);
    record_data = document.getElementById("record_data").value;
    if (record_type == "CNAME" || record_type == "NS") {
        return { type: record_type, domain: record_name, ttl: record_ttl, host: record_data }
    } else if (record_type == "MX") {
        record_priority = parseInt(document.getElementById("record_priority").value);
        return { type: record_type, domain: record_name, ttl: record_ttl, priority: record_priority, host: record_data }
    }  else if (record_type == "TXT") {
        record_priority = parseInt(document.getElementById("record_priority").value);
        return { type: record_type, domain: record_name, ttl: record_ttl, data: record_data }
    } else if (record_type == "SRV") {
        record_priority = parseInt(document.getElementById("record_priority").value);
        record_weight = parseInt(document.getElementById("record_weight").value);
        record_port = parseInt(document.getElementById("record_port").value);
        return { type: record_type, domain: record_name, ttl: record_ttl, priority: record_priority, weight: record_weight, port: record_port, host: record_data }
    }
    return { type: record_type, domain: record_name, ttl: record_ttl, addr: record_data }
}

function onLoad() {
    external.invoke(JSON.stringify({cmd: 'loaded'}));
}

function openTab(element, tabName) {
    // Declare all variables
    var i, tabContent, tabLinks;

    // Get all elements with class="content" and hide them
    tabContent = document.getElementsByClassName("content");
    for (i = 0; i < tabContent.length; i++) {
        tabContent[i].className = "content is-hidden";
    }

    // Get all elements with class="tablinks" and remove the class "active"
    tabLinks = document.getElementsByClassName("is-active");
    for (i = 0; i < tabLinks.length; i++) {
        tabLinks[i].className = "";
    }

    // Show the current tab, and add an "active" class to the button that opened the tab
    document.getElementById(tabName).className = "content";
    element.className = "is-active";
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

function createDomain() {
    new_domain = document.getElementById("new_domain").value;
    //new_dom_records = document.getElementById("new_domain_records").value;
    new_dom_records = JSON.stringify(recordsBuffer);
    new_dom_tags = document.getElementById("new_domain_tags").value;
    external.invoke(JSON.stringify({cmd: 'createDomain', name: new_domain, records: new_dom_records, tags: new_dom_tags}));
}

function changeDomain() {
    domain = document.getElementById("change_domain").value;
    dom_records = document.getElementById("change_domain_records").value;
    dom_tags = document.getElementById("change_domain_records").value;
    external.invoke(JSON.stringify({cmd: 'changeDomain', name: domain, records: dom_records, tags: dom_tags}));
}

function renewDomain() {
    domain = document.getElementById("renew_domain").value;
    days = document.getElementById("renew_domain_extend_days").value;
    external.invoke(JSON.stringify({cmd: 'renewDomain', name: domain, days: days}));
}

function transferDomain() {
    domain = document.getElementById("transfer_domain").value;
    new_owner = document.getElementById("transfer_domain_transfer_owner").value;
    external.invoke(JSON.stringify({cmd: 'transferDomain', name: domain, owner: new_owner}));
}

function sendAction(param) {
    external.invoke(JSON.stringify(param));
}

function onDomainChange(element) {
    external.invoke(JSON.stringify({cmd: 'checkDomain', name: element.value}));
}

function domainAvailable(available) {
    input = document.getElementById("new_domain");
    button = document.getElementById("new_domain_button");
    if (available) {
        input.className = "input";
        button.disabled = false
    } else {
        input.className = "input is-danger";
        button.disabled = true
    }
}

function showModalDialog(text, callback) {
    message = document.getElementById("modal_text");
    message.textContent = text;

    button_positive = document.getElementById("modal_positive_button");
    button_positive.onclick = function() {
        callback();
        dialog = document.getElementById("modal_dialog");
        dialog.className = "modal";
    };

    button_negative = document.getElementById("modal_negative_button");
    button_negative.onclick = function() {
        dialog = document.getElementById("modal_dialog");
        dialog.className = "modal";
    }

    dialog = document.getElementById("modal_dialog");
    dialog.className = "modal is-active";
}

function showWarning(text) {
    warning = document.getElementById("notification_warning");
    message = document.getElementById("warning_text");
    message.innerHTML = text;

    warning.className = "notification is-warning";
    button = document.getElementById("close");
    button.onclick = function() {
        message.value = "";
        warning.className = "notification is-warning is-hidden";
    }
    setTimeout(button.onclick, 5000);
}

function showMiningIndicator(visible) {
    indicator = document.getElementById("mining_indicator");
    if (visible) {
        indicator.style.visibility = 'visible';
    } else {
        indicator.style.visibility = 'hidden';
    }
}

function miningIndicatorClick(element) {
    showModalDialog("Do you really want to stop mining?", function() {
        external.invoke(JSON.stringify({cmd: 'stopMining'}));
    });
}

function keystoreChanged(path, pub_key) {
    if (path == '') {
        path = "In memory";
    }
    key_file_name = document.getElementById("key_file_name");
    key_file_name.innerHTML = path;
    key_file_key = document.getElementById("key_public_key");
    key_file_key.innerHTML = pub_key;
}