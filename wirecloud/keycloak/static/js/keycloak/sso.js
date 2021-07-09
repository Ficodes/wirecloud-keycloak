/*
 *     Copyright (c) 2021 Future Internet Consulting and Development Solutions S.L.
 *
 *     This file is part of Wirecloud Platform.
 *
 *     Wirecloud Platform is free software: you can redistribute it and/or
 *     modify it under the terms of the GNU Affero General Public License as
 *     published by the Free Software Foundation, either version 3 of the
 *     License, or (at your option) any later version.
 *
 *     Wirecloud is distributed in the hope that it will be useful, but WITHOUT
 *     ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *     FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public
 *     License for more details.
 *
 *     You should have received a copy of the GNU Affero General Public License
 *     along with Wirecloud Platform.  If not, see
 *     <http://www.gnu.org/licenses/>.
 *
 */

/* globals Wirecloud */


((utils) => {
    "use strict";

    const login_status_iframe = document.createElement("iframe");
    const iframe_url = new URL(Wirecloud.URLs.KEYCLOAK_LOGIN_STATUS_IFRAME);
    login_status_iframe.setAttribute("src", iframe_url);
    login_status_iframe.setAttribute("title", "keycloak-silent-check-sso");
    login_status_iframe.style.display = "none";
    document.body.appendChild(login_status_iframe);

    Wirecloud.addEventListener("loaded", () => {
        const interval = setInterval(() => {
            const client_id = Wirecloud.contextManager.get("keycloak_client_id");
            const session_state = Wirecloud.contextManager.get("keycloak_session");
            // string literals/templates are not supported by the django-compressor module used by WireCloud <= 1.4
            login_status_iframe.contentWindow.postMessage(client_id + " " + session_state, iframe_url.origin);
        }, 1500);

        const handleChange = function handleChange(event) {
            if (event.origin !== iframe_url.origin || login_status_iframe.contentWindow !== event.source) {
                return;
            }

            window.removeEventListener("message", handleChange);
            if (event.data === "changed") {
                Wirecloud.login(true);
            } else {
                Wirecloud.logout();
            }
        };

        const processResponse = function processResponse(event) {
            if (event.origin !== iframe_url.origin || login_status_iframe.contentWindow !== event.source) {
                return;
            }

            if (event.data === "changed") {
                clearInterval(interval);
                window.removeEventListener("message", processResponse);
                const session_state = Wirecloud.contextManager.get("keycloak_session");
                let action;
                if (session_state === "") {
                    action = () => Wirecloud.login();
                } else {
                    action = () => {
                        const client_id = Wirecloud.contextManager.get("keycloak_client_id");
                        window.addEventListener("message", handleChange);
                        // string literals/templates are not supported by the django-compressor module used by WireCloud <= 1.4
                        login_status_iframe.contentWindow.postMessage(client_id + " ", iframe_url.origin);
                    };
                }

                if (Wirecloud.contextManager.get("mode") !== "embedded") {
                    const dialog = new Wirecloud.ui.MessageWindowMenu(
                        utils.gettext("Browser will be reloaded to accomodate to the new session info"),
                        utils.gettext("User Session Updated")
                    );
                    dialog.addEventListener("hide", action);
                    dialog.show();
                } else {
                    action();
                }
            }
        };
        window.addEventListener("message", processResponse);
    });
})(Wirecloud.Utils);
