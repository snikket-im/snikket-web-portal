var open_modal = function(a_el) {
    var modal_id = "" + a_el.getAttribute("href").split("#")[1];
    var modal_el = document.getElementById(modal_id);
    modal_el.setAttribute("aria-modal", "true");
    modal_el.removeAttribute("aria-hidden");
    modal_el.style.setProperty("display", "block");
};

var close_modal = function(modal_el) {
    modal_el.removeAttribute("aria-modal");
    modal_el.setAttribute("aria-hidden", "true");
    modal_el.style.setProperty("display", "none");
};

var find_tabbox_el = function(tab_content_el) {
    var current = tab_content_el;
    while (current) {
        if (current.classList.contains("tabbox")) {
            return current;
        }
        current = current.parentNode;
    };
    return null;
};

var clear_active_tab = function(tabbox_el) {
    var nav_el = tabbox_el.firstChild;
    var child = nav_el.firstChild;
    while (child) {
        child.setAttribute("aria-selected", "false");
        child.classList.remove("active");
        child = child.nextSibling;
    }

    var child = nav_el.nextSibling;
    while (child) {
        if (child.classList.contains("tab-pane")) {
            child.classList.remove("active");
        }
        child = child.nextSibling;
    }
};

var select_tab = function(tab_header_el) {
    var tab_id = "" + tab_header_el.getAttribute("href").split("#")[1];
    var tab_el = document.getElementById(tab_id);
    clear_active_tab(find_tabbox_el(tab_el));
    tab_el.classList.add("active");
    tab_header_el.classList.add("active");
    tab_header_el.setAttribute("aria-selected", "true");
};

var apply_qr_code = function(target_el) {
    new QRCode(target_el, target_el.dataset.qrdata);
};
