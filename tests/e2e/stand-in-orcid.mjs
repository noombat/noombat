// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * A stand-in for ORCID's authorisation page, which the end-to-end stack
 * points ORCID at (`NOOMBAT_ORCID_BASE_URI`), so a spec can follow a
 * sign-in's start to the provider. It answers that one address and
 * nothing else. Usage: node stand-in-orcid.mjs [port]
 */

import { createServer } from "node:http";
import process from "node:process";

const port = Number(process.argv[2] ?? 8790);

createServer((request, response) => {
  if (request.method === "GET" && request.url?.startsWith("/oauth/authorize?")) {
    response.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    response.end("<!doctype html><title>Stand-in ORCID</title><p>Stand-in ORCID</p>");
    return;
  }
  response.writeHead(404).end();
}).listen(port, "127.0.0.1");
