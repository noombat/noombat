// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * The messages a page holds, by IMAP UID, so that connecting again asks
 * only for newer ones and none is shown twice. Kept apart from the page,
 * so it is tested without one.
 */
export class Received {
  private readonly held = new Set<number>();
  private newestUid = 0;
  private uidValidity: number | undefined;

  /** Records the mailbox's UIDVALIDITY, and when it changed, forgets
   *  every UID held, which name other messages now. Whether it changed;
   *  an unknown one changes nothing. */
  inMailbox(uidValidity: number | null | undefined): boolean {
    if (uidValidity === null || uidValidity === undefined) return false;
    const changed = this.uidValidity !== undefined && this.uidValidity !== uidValidity;
    this.uidValidity = uidValidity;
    if (changed) {
      this.held.clear();
      this.newestUid = 0;
    }
    return changed;
  }

  /** Whether the message `uid` is new to the page, which holds it from
   *  then on. One without a UID (0) is always new. */
  take(uid: number): boolean {
    if (uid <= 0) return true;
    if (this.held.has(uid)) return false;
    this.held.add(uid);
    this.newestUid = Math.max(this.newestUid, uid);
    return true;
  }

  /** The UID of the newest message held, after which to ask; 0 for none. */
  get newest(): number {
    return this.newestUid;
  }
}
