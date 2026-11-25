// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * Island entry point for the real-time Chatmail chat interface.
 *
 * The server-rendered template places a `<div id="chat-mount">` with
 * `data-ws-url`, `data-chatmail-addr`, `data-username`, and
 * `data-locale` attributes. This script hydrates that element into
 * an interactive chat interface backed by WebSocket, OpenPGP.js, and
 * the Autocrypt Level 1 state machine.
 */

import { render, setTrustedTypesPolicy } from "solid-js/web";
import { solidPolicy } from "../trusted-types";
import Chat from "./Chat";
import "./chat.css";

// Solid builds its elements from template strings, which the page's
// policy accepts only through the policy made for them.
if (solidPolicy) setTrustedTypesPolicy(solidPolicy);

const mount = document.getElementById("chat-mount");

if (mount) {
  const wsUrl = mount.dataset.wsUrl ?? "";
  const chatmailAddr = mount.dataset.chatmailAddr ?? "";
  const username = mount.dataset.username ?? "";
  const needsSetup = mount.dataset.needsSetup === "true";
  const hasPassword = mount.dataset.hasPassword === "true";
  const locale = mount.dataset.locale ?? document.documentElement.lang ?? "en-US";

  render(
    () => (
      <Chat
        wsUrl={wsUrl}
        chatmailAddr={chatmailAddr}
        username={username}
        locale={locale}
        needsSetup={needsSetup}
        hasPassword={hasPassword}
      />
    ),
    mount,
  );
}
