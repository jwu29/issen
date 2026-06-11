# Workshop Delivery Kanban — TEMPLATE (reusable)

> **How to reuse:** copy this file to `docs/workshops/<event-slug>.md`, fill the **Event**
> block and the **Countdown** dates, then work cards left → right across the columns.
> One card per line: `- [ ] **ID** Card — owner · due (T-N)`. When a card is done, move it
> to **Done** with the date.
>
> **Scope:** this board is the *delivery / logistics* run-up — venue, materials, USB
> distribution, day-of. The *content / CTF / tool* development lives in its own board
> alongside this one (e.g. `KANBAN.md` in this folder). Keep the two separate: this one is
> "can we hand it out and run the room," that one is "is the material true."

## Event
- **Event:**
- **Date / time:**
- **Venue / room:**
- **Format:** _(link the content board / format doc, e.g. `DESIGN.md`)_
- **Expected attendees:**
- **Distribution:** N× USB‑C sticks + backup download link / QR
- **Instructor(s):**

## Countdown
_T‑0 = event day. Fill the dates from the event date backwards._

| Milestone | Target | Date |
|---|---|---|
| Content freeze (slides + handout final) | T‑7 | |
| Procure USB sticks (in hand) | T‑7 | |
| Build + verify ONE master stick | T‑3 | |
| End‑to‑end lab dry‑run on a clean machine | T‑3 | |
| **All N USB sticks cloned + checksum‑verified** | **T‑2** | |
| Print handouts / feedback forms | T‑2 | |
| Pack kit (sticks, adapters, power, signage) | T‑1 | |
| Run workshop | T‑0 | |
| Share slides + collect feedback | T+1 | |

## Backlog
- [ ] **CONTENT-1** Finalize slides + student handout
- [ ] **CONTENT-2** Freeze + package the CTF data files for distribution (fixed set + checksums)
- [ ] **CONTENT-3** End‑to‑end lab dry‑run on a CLEAN machine (no dev tooling) — proves the handout
- [ ] **DIST-1** Source N× USB‑C sticks — capacity ≥ dataset size + headroom; note the data size
- [ ] **DIST-2** Build ONE master stick (data files + README + `SHA256SUMS`); verify it boots/opens
- [ ] **DIST-3** Clone master → N sticks (parallel via a powered USB hub); verify checksum on EACH; label
- [ ] **DIST-4** Backup distribution: a download link + printed QR (stick failure / extra attendees)
- [ ] **LOGI-1** Confirm venue: room, AV / projector / HDMI, Wi‑Fi, power strips & outlet count
- [ ] **LOGI-2** Confirm attendee count → finalize stick count (+spares)
- [ ] **LOGI-3** Print handouts + feedback forms; name badges if needed
- [ ] **DAY-1** Run‑of‑show / minute‑by‑minute facilitator timing + setup checklist

## To Do (scheduled)

## In Progress

## Blocked

## Done

---

## Notes / daily log

### <date>
-
