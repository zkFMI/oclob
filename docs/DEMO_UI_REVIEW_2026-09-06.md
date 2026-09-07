# Demo UI review — 2026-09-06

Status: OCLOB build 5 is integrated, but release acceptance is still open. The
existing regular demo service has not been replaced. This review does not certify
production identity, network privacy, or accessibility compliance. Native
public-reader observations are recorded below; corporate browser login and order
submission are not yet implemented.

## Scope and implementation

Claude Fable 5.1, high effort, revised the existing OCLOB and QOMM demo
frontends. The parent integrated OCLOB build 5 into this checkout without
replacing backend code or financial rules. QOMM build 11 remains isolated until
its frontend-only changes can be merged without disturbing its running native
acceptance test.

The OCLOB screen now presents available and reserved funds/inventory separately,
then the order form, own-order status, public book, and React Flow processing
diagram. Cryptographic identifiers and raw server messages are secondary details.
Queued orders are not described as settled. The form qualifies illustrative
proceeds by limit price, full quantity, partial fills, and price improvement.
Visibility wording distinguishes this research server's role-filtered display
from the native protocol's cryptographic protections.

## Observed steps

1. Market operator at 1440 × 1000: the public book, processing history, and
   complete network diagram fit their columns. Plain-language history and the
   research-mode limitation are visible.
2. Market operator at 390 × 844: role controls, four summary cards, and public
   book precede the diagram. No clipping was observed in the captured viewport.
3. Maker at 390 × 844: available/reserved balances and the form remain readable;
   the explanation does not promise full execution or a fixed receipt amount.

Parent captures, saved and visually inspected in this audit:

- `/tmp/oclob-ui-v3-parent-desktop-20260906.png`
- `/tmp/oclob-ui-v3-parent-narrow-20260906.png`
- `/tmp/oclob-ui-v3-parent-maker-form-20260906.png`

These captures came from the actual research server at port 28811, not a mocked
API. Fable separately exercised sell 40 at 100 followed by buy 40 at 100, observed
the research ledger update and balance changes, and checked simulated node
stop/resume. This is a single-host research flow, not independent operators or
the native Avalanche acceptance path.

## Integration checks

The earlier merged gate 011 on `softbank-l40s` passed workspace formatting and
Clippy, the node/demo Rust tests, the related TypeScript configurations, Vite
build, five frontend tests, and JavaScript syntax. The frontend tests chiefly
cover the native book components; they do not establish complete coverage of the
legacy page's copy.

Log: `/tmp/oclob-ui-gateway-final-011-20260906.log`

After integrating build 5, the parent started the complete `make release-gate`
on Softbank. Its SSH connection was closed during the release-profile Rust
compile, so that attempt ended with infrastructure error 255 and is not a pass.
It must be rerun when Softbank or Omen is reachable. Log:
`/tmp/oclob-release-gate-20260906.log`.

## Remaining acceptance

- OCLOB build 5 is integrated byte-for-byte for the five generated static files.
  The parent verified the legacy research service at desktop and 390 px: the
  portfolio totals no longer wrap, the order price/quantity remains one line,
  the status badge sits below it, document width equals 390 px, and the browser
  emitted no warning or error. The merged release gate still needs a clean
  remote completion.
- Integrate QOMM build 11 only after its running native acceptance test has
  completed, preserving unrelated backend work.
- Verify the revised native OCLOB browser against its actual network services.
- Replace the regular demo services only after the final checks, preserving
  existing state and a recoverable old image; inspect the deployed revision.
- Keyboard, screen-reader, and comprehensive contrast coverage remain unverified.

## Native public reader — run 009

The actual seven-container MPC / five-validator acceptance run completed with
exit 0. The browser used its real HTTP public reader at port 19880, not mocked
responses. The backend receipt is `artifacts/oclob_native_corporate_gateway.json`;
source hashes and four sanitized gateway reports are bound in
`artifacts/oclob_native_corporate_gateway_sources.json`. This is single-host
functional smoke evidence, not independent operators or WAN evidence.

1. Before a valid book existed, desktop and 390 px views explained the missing
   data and displayed no invented prices (`/tmp/oclob-native009-01-unavailable-desktop.png`,
   `/tmp/oclob-native009-02-unavailable-narrow.png`).
2. After actual settlement, the desktop and narrow book showed sequence 4,
   sell levels 100 × 15 and 101 × 30, seven signatures, and DeFMI height 16
   (`/tmp/oclob-native009-03-settled-desktop.png`,
   `/tmp/oclob-native009-04-settled-narrow.png`). The desktop graph was readable;
   the narrow book had no horizontal overflow.
3. After the run, loss of a valid feed removed prices instead of keeping stale
   quotes. The graph showed unconfirmed signatures and unavailable settlement
   evidence. Normal 1440 → 390 resizing retained readable node cards; console
   errors and warnings were empty (`/tmp/oclob-native009-07-normal-resize.png`).

The attempted full-page capture `05-settled-narrow-full` was rejected because it
duplicated the page and disturbed React Flow's viewport. The subsequent tiny
diagram recovered with Fit View (`06-narrow-refit`); normal viewport resizing
did not reproduce the defect. No speculative product fix was made for this
capture-only observation. This does not establish comprehensive zoom or
assistive-technology coverage.

## QOMM parent review follow-up

Fable build 11 is the final QOMM frontend candidate. It corrects the eight-Maker
card density and narrow graph fitting as well as the misleading claims previously
shown in plain-comparison and rejected-price states. It remains isolated pending
integration and parent verification; earlier build 9 must not be deployed.

## OCLOB build 4 — parent transaction check

The parent submitted a resting sell of 40 at 100 and then a buy of 40 at 100
through the actual browser on port 28811. Before execution, the Maker displayed
9,960 available units and 40 reserved units. After execution, the Taker displayed
99,996,000 cash and 10,040 units, with neither cash nor units reserved. The
actual response reported `MP-SPDZ malicious-shamir`, seven parties,
`threshold_zkpi: true`, zero post-match participant signatures, and ledger
height 5. This is the research server's in-process ledger, not native Avalanche.

Accepted captures: `/tmp/oclob-ui-final-taker-balances.png` (1440 × 1000),
`/tmp/oclob-ui-final-taker-narrow.png` (390 × 844). Narrow scroll width equalled
390, and the browser reported no warnings or errors. The earlier
`maker-resting-desktop` and `taker-settled-desktop` captures were not accepted as
balance evidence because they were scrolled below the balances. Wheel movement
inside React Flow zoomed the graph; Fit View restored the expected layout.

Build 5 fixes the two remaining text defects: the cash-card total label no longer
wraps vertically, and the completed-status badge no longer squeezes the order
price/quantity into several short lines. The parent reproduced both corrected
states at 390 × 844 and found no horizontal overflow or browser warning/error.

Final merged gate 011 passed on Softbank: workspace formatting and Clippy,
node/demo Rust tests, all related frontend TypeScript checks, Vite build,
five frontend tests, and JavaScript syntax. Log:
`/tmp/oclob-ui-gateway-final-011-20260906.log`. Gate 010 failed formatting only;
the follow-up changed line wrapping of a probe error message, not behavior.
