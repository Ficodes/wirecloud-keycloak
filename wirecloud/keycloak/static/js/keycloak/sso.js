(() => {
    "use strict";

    const login_status_iframe = document.createElement("iframe");
    const iframe_url = new URL(Wirecloud.URLs.KEYCLOAK_LOGIN_STATUS_IFRAME);
    login_status_iframe.setAttribute("src", iframe_url);
    login_status_iframe.setAttribute("title", "keycloak-silent-check-sso");
    login_status_iframe.style.display = "none";
    document.body.appendChild(login_status_iframe);

    const interval = setInterval(() => {
        const client_id = Wirecloud.contextManager.get("keycloak_client_id");
        const session_state = Wirecloud.contextManager.get("keycloak_session");
        login_status_iframe.contentWindow.postMessage(`${client_id} ${session_state}`, iframe_url.origin);
    }, 1500);

    const handleChange = function handleChange(event) {
        if (event.origin !== iframe_url.origin || login_status_iframe.contentWindow !== event.source) {
            return;
        }

        window.removeEventListener("message", handleChange);
        const dialog = new Wirecloud.ui.MessageWindowMenu(
            "Browser will be reloaded to accomodate to the new session info",
            "User Session Updated"
        );
        if (event.data === "changed") {
            dialog.addEventListener("hide", () => Wirecloud.login());
        } else {
            dialog.addEventListener("hide", () => Wirecloud.logout());
        }
        dialog.show();
    };

    const processResponse = function processResponse(event) {
        if (event.origin !== iframe_url.origin || login_status_iframe.contentWindow !== event.source) {
            return;
        }

        if (event.data === "changed") {
            clearInterval(interval);
            window.removeEventListener("message", processResponse);
            const session_state = Wirecloud.contextManager.get("keycloak_session");
            if (session_state === "") {
                const dialog = new Wirecloud.ui.MessageWindowMenu(
                    "Browser will be reloaded to accomodate to the new session info",
                    "User Session Updated"
                );
                dialog.addEventListener("hide", () => Wirecloud.login());
                dialog.show();
            } else {
                const client_id = Wirecloud.contextManager.get("keycloak_client_id");
                window.addEventListener("message", handleChange);
                login_status_iframe.contentWindow.postMessage(`${client_id} `, iframe_url.origin);
            }
        }
    };
    window.addEventListener("message", processResponse);
})();
