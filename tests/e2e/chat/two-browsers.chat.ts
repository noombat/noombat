// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

// Two members who use only the chat page, each in a browser context of
// their own, against the chat interop stack: tests/chat-interop/run.sh
// runs this as its check 19, with the members' passwords from
// fixture-credential.sh.
//
// grace sets chat up while her key cannot be published, and unlocking
// later publishes it. frank writes to her first, by handle, on the key her
// instance publishes; the page tells him so, with its fingerprint, and his
// panel shows that fingerprint as the instance's, while grace's shows it
// as her own. grace reads his message, signed, as it arrives, and her
// reply reaches him. Connected again, her page asks only for messages
// newer than it holds; told the mailbox's UIDs were assigned again, it
// asks for all of them; either way it shows each message once.

import { expect, test, type Browser, type Page, type WebSocketRoute } from "@playwright/test";

const DOMAIN = process.env.NOOMBAT_DOMAIN ?? "test.local";
const CHAT_DOMAIN = process.env.CHAT_DOMAIN ?? "chat.test.local";
const GRACE = `grace@${CHAT_DOMAIN}`;
const FRANK = `frank@${CHAT_DOMAIN}`;

/** Deriving keys from a password and a relay round trip take a while. */
const SLOW = { timeout: 60_000 };

function password(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set: run this through tests/chat-interop/run.sh`);
  return value;
}

/** A browser context of `username`'s own, signed in through the login page. */
async function signIn(browser: Browser, username: string, secret: string): Promise<Page> {
  const page = await (await browser.newContext()).newPage();
  await page.goto("/auth/login");
  await page.locator("#login-username").fill(username);
  await page.locator("#login-password").fill(secret);
  await page.locator("#login-form button[type=submit]").click();
  await page.waitForURL((url) => url.pathname === "/", SLOW);
  return page;
}

interface Frame {
  type?: string;
  uid?: number;
  since_uid?: number;
  uid_validity?: number | null;
}

/** The page's chat WebSocket, passed through to the server frame by frame,
 *  so that the test sees what each side sends, can drop the connection as
 *  a network failure would, and can make the next `ready` name a mailbox
 *  whose UIDs were assigned again. */
async function routeChatSocket(page: Page) {
  const opened: WebSocketRoute[] = [];
  const asked: number[] = [];
  const acked: number[] = [];
  const validities: (number | null | undefined)[] = [];
  let renumber = false;
  await page.routeWebSocket("**/api/v1/chat/ws", (socket) => {
    const server = socket.connectToServer();
    socket.onMessage((data) => {
      const frame = JSON.parse(String(data)) as Frame;
      if (frame.type === "fetch") asked.push(frame.since_uid ?? -1);
      if (frame.type === "ack") acked.push(frame.uid ?? -1);
      server.send(data);
    });
    server.onMessage((data) => {
      const frame = JSON.parse(String(data)) as Frame;
      if (frame.type === "ready") {
        validities.push(frame.uid_validity);
        if (renumber && typeof frame.uid_validity === "number") {
          renumber = false;
          socket.send(JSON.stringify({ ...frame, uid_validity: frame.uid_validity + 1 }));
          return;
        }
      }
      socket.send(data);
    });
    opened.push(socket);
  });
  return {
    /** The `since_uid` of each fetch the page sent. */
    asked: () => [...asked],
    /** The UID of each message the page acknowledged, once it showed it. */
    acked: () => [...acked],
    /** The UIDVALIDITY each `ready` named, as the server sent it. */
    validities: () => [...validities],
    drop: async () => opened.at(-1)?.close(),
    renumberNextMailbox: () => {
      renumber = true;
    },
  };
}

/** Waits for the chat page's own view, which shows once chat is unlocked. */
async function chatOpen(page: Page): Promise<void> {
  await expect(page.getByPlaceholder("Write a message…")).toBeVisible(SLOW);
}

async function setUpChat(page: Page, secret: string): Promise<void> {
  await page.goto("/chat");
  await page.getByPlaceholder("Password").fill(secret);
  await page.getByRole("button", { name: "Set up chat" }).click();
  await chatOpen(page);
}

/** Unlocks the chat page already loaded. */
async function unlock(page: Page, secret: string): Promise<void> {
  await page.getByPlaceholder("Password").fill(secret);
  await page.getByRole("button", { name: "Unlock" }).click();
  await chatOpen(page);
}

/** The status of the instance's answer for `address`'s published key,
 *  asked from the page, as the chat page asks. */
async function keyLookup(page: Page, address: string): Promise<number> {
  return page.evaluate(
    async (url) => (await fetch(url)).status,
    `/api/v1/chat/keys/${encodeURIComponent(address)}`,
  );
}

async function send(page: Page, to: string, body: string): Promise<void> {
  await page.locator(".noombat-chat__recipient").fill(to);
  await page.getByPlaceholder("Write a message…").fill(body);
  await page.getByRole("button", { name: "Send", exact: true }).click();
}

/** The fingerprint the open verification panel shows in the row `label`. */
function fingerprintIn(page: Page, label: string) {
  return page
    .locator("#chat-verify-panel .noombat-chat__verify-row", { hasText: label })
    .locator("code");
}

/** A message received, decrypted, with its signature verified. */
function received(page: Page, body: string) {
  return page.locator(".noombat-chat__bubble", { hasText: body }).filter({ hasText: "verified" });
}

/** Every bubble showing `body`. */
function shown(page: Page, body: string) {
  return page.locator(".noombat-chat__bubble", { hasText: body });
}

test("first contact on a published key, with its fingerprint, and a reply", async ({ browser }) => {
  const gracePassword = password("CHAT_GRACE_PASSWORD");
  const frankPassword = password("CHAT_FRANK_PASSWORD");

  // grace's key fails to publish at setup; her next unlock publishes it.
  const grace = await signIn(browser, "grace", gracePassword);
  const graceSocket = await routeChatSocket(grace);
  await grace.route("**/api/v1/me/chat_key", (route) => route.abort());
  await setUpChat(grace, gracePassword);
  expect(await keyLookup(grace, GRACE)).toBe(404);
  // A new page load first, so nothing the setup's page still had to send
  // gets through: only the unlock below can publish.
  await grace.goto("/chat");
  await grace.unroute("**/api/v1/me/chat_key");
  await unlock(grace, gracePassword);
  await expect.poll(() => keyLookup(grace, GRACE), SLOW).toBe(200);

  const frank = await signIn(browser, "frank", frankPassword);
  await setUpChat(frank, frankPassword);

  // frank names grace by handle; the page finds her address and the key
  // her instance publishes, and says so with its fingerprint.
  await send(frank, `@grace@${DOMAIN}`, "Hello grace, from frank.");
  const notice = frank.locator(".noombat-chat__notice", {
    hasText: `Using the key published for ${GRACE}, fingerprint`,
  });
  await expect(notice).toBeVisible(SLOW);
  const announced = /fingerprint ([0-9A-Fa-f ]+)\./.exec((await notice.textContent()) ?? "")?.[1];
  expect(announced, "the notice names a fingerprint").toBeTruthy();
  await expect(frank.locator(".noombat-chat__recipient")).toHaveValue(GRACE);

  // His panel shows that key as the instance's; hers, as her own.
  await frank.getByRole("button", { name: "Verify keys" }).click();
  await expect(fingerprintIn(frank, "Their fingerprint")).toHaveText(announced ?? "", SLOW);
  await expect(
    frank.getByText("Provided by this instance; not yet seen in a message from them."),
  ).toBeVisible();
  await grace.getByRole("button", { name: "Verify keys" }).click();
  await expect(fingerprintIn(grace, "Your fingerprint")).toHaveText(announced ?? "", SLOW);

  // grace reads it, signed by frank, and answers from her contacts.
  await expect(received(grace, "Hello grace, from frank.")).toBeVisible(SLOW);
  await grace.getByRole("button", { name: FRANK }).click();
  await grace.getByPlaceholder("Write a message…").fill("Hello frank, from grace.");
  await grace.getByRole("button", { name: "Send", exact: true }).click();
  await expect(received(frank, "Hello frank, from grace.")).toBeVisible(SLOW);
  // Her key for him came with his message, not from the instance.
  await expect(grace.locator(".noombat-chat__notice", { hasText: "Using the key" })).toHaveCount(0);

  // Connected again, her page asks only for what is newer than the newest
  // it holds, and frank's next message arrives.
  const newest = Math.max(...graceSocket.acked());
  let fetches = graceSocket.asked().length;
  await graceSocket.drop();
  await expect.poll(() => graceSocket.asked().length, SLOW).toBe(fetches + 1);
  expect(graceSocket.asked().at(-1)).toBe(newest);
  await send(frank, GRACE, "Hello again, grace.");
  await expect(received(grace, "Hello again, grace.")).toBeVisible(SLOW);

  // Told that the mailbox's UIDs were assigned again, her page forgets
  // those it holds and asks for every message. Once it has shown each, by
  // acknowledging it, none is shown twice.
  graceSocket.renumberNextMailbox();
  fetches = graceSocket.asked().length;
  const acks = graceSocket.acked().length;
  await graceSocket.drop();
  await expect.poll(() => graceSocket.asked().length, SLOW).toBe(fetches + 1);
  expect(graceSocket.asked().at(-1)).toBe(0);
  await expect.poll(() => graceSocket.acked().length, SLOW).toBe(acks + 2);
  await expect(shown(grace, "Hello grace, from frank.")).toHaveCount(1);
  await expect(shown(grace, "Hello again, grace.")).toHaveCount(1);
  expect(graceSocket.validities().every((v) => typeof v === "number")).toBe(true);
});
