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

import { render } from "solid-js/web";
import Chat from "./Chat";
import "./chat.css";

const mount = document.getElementById("chat-mount");

if (mount) {
  const wsUrl = mount.dataset.wsUrl ?? "";
  const chatmailAddr = mount.dataset.chatmailAddr ?? "";
  const username = mount.dataset.username ?? "";
  const locale =
    mount.dataset.locale ?? document.documentElement.lang ?? "en-US";

  render(
    () => (
      <Chat
        wsUrl={wsUrl}
        chatmailAddr={chatmailAddr}
        username={username}
        locale={locale}
      />
    ),
    mount,
  );
}
