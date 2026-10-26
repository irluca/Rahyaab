# Dashboard patterns borrowed from Nexora Panel (ideas only)

Source: https://github.com/nexora-vpn/panel and its docs site
(docs.nexora-panel.org). Nexora's panel source is NOT public — it ships
binaries and documentation only — so nothing here is copied code.
Nexora is also a user-management panel; Rahyaab borrows only layout
and presentation patterns, never user/config management. Rahyaab's
scope stays: tunnels between fleet servers, their health, and healer
control. PasarGuard is never touched.

Patterns worth adopting in Rahyaab Phase 3:

- Screen in three parts: sidebar (pages by permission), header (page
  name, search, theme, account menu), page body. Banners between
  header and page for licence/update notices.
- Sidebar folds to an icon rail on desktop, drawer on phone; a pin
  keeps it open.
- Summary strip of counters at the top of a page; clicking a counter
  filters the rows below (click again clears).
- Dashboard tiles: small live gauges/charts/readouts, draggable by
  header, pinnable per account, refreshing every few seconds while
  the page is open. Groups: hub host health, fleet overview, per-pair
  (our equivalent of per-node) tiles.
- A dash means "not reported", never zero — applies to our charts too:
  never fake a metric we did not measure.
- Command palette (Ctrl-K): jump to pages and actions by typing.
- Theme: light / dark / high contrast, accent colours, compact
  density, stored per browser. Persian switches the whole layout RTL.
- List pages share one behaviour: summary strip, Add + search in the
  header row, row actions with a ⋮ overflow, checkboxes for bulk
  actions, destructive actions ask first, dialogs keep unsaved edits
  on error.
- Getting-started card that ticks steps off and disappears when done
  — our equivalent: add first server, add second server, form a pair,
  run a benchmark, deploy a tunnel.
