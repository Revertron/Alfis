function openTab(element, tabName) {
    // Declare all variables
    var i, tabContent, tabLinks;

    // Get all elements with class="content" and hide them
    tabContent = document.getElementsByClassName("content");
    for (i = 0; i < tabContent.length; i++) {
        tabContent[i].className = "context is-hidden";
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
    key_name = document.getElementById("load_key_name").value;
    key_pass = document.getElementById("load_key_password").value;
    external.invoke(JSON.stringify({cmd: 'loadKey', name: key_name, pass: key_pass}));
}

function createKey() {
    key_name = document.getElementById("create_key_name").value;
    key_pass = document.getElementById("create_key_password").value;
    external.invoke(JSON.stringify({cmd: 'createKey', name: key_name, pass: key_pass}));
}

function createDomain() {
    new_domain = document.getElementById("new_domain").value;
    new_dom_records = document.getElementById("new_domain_records").value;
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