# Console UI

The server-rendered console uses local CSS, JavaScript and system fonts. It
does not require a frontend framework, a build step or a font CDN.

## Structure

- `templates/base.html` owns the sidebar, header, page actions and footer.
  Pages fill `header_title`, `header_buttons` and `content`. Page actions
  render inside the main content. Navigation is included once by the shell.
- `templates/_haproxy_nav.html` defines the navigation groups and the parent
  destinations for detail and edit pages. Keep its destination list aligned
  with the Flask routes. Administrative navigation follows `g.is_superadmin`;
  server-side access checks remain authoritative.
- `static/css/styles.css` owns theme tokens, the shell, shared components and
  small layout utilities. `static/css/pages.css` owns page-specific layouts
  and states. Both follow the declared CSS layer order. Add page rules to the
  `pages` layer and explicit utility overrides to `utilities`.
- `static/js/theme.js` applies the theme before CSS loads. It follows the OS
  until the user chooses a theme, and keeps the existing `theme` storage key.
  Storage is optional. Theme-aware charts use CSS variables for their colors.
- `static/js/nav.js` manages persisted disclosure groups and the mobile drawer.
  The drawer traps keyboard focus, makes the background inert and closes with
  Escape or a backdrop click. Native disclosure navigation also works without
  JavaScript.

## Conventions

Use the shared tokens for text, surfaces, borders and semantic status colors.
Keep status text or icons alongside colors. Use `hidden` for visibility state;
the shared reset deliberately makes it stronger than component display rules.
Keep wide data and editing tables inside a scrolling wrapper, rather than
letting the whole page scroll horizontally. Menus inside a table expand in
the row so the table's scrolling boundary cannot clip their actions.

Keep IDs, field names, action values and `data-*` bindings stable when changing
markup: the existing scripts and forms depend on them. Decorative inline CSS
and template-local style blocks have been removed. Dynamic geometry, chart
colors and progress widths may still be set by scripts.

## Verification

Run the Python regression suite, JavaScript behavior tests and ESLint. The
shell tests cover role visibility, safe account text, current edit-page
navigation and placement of page actions. Theme behavior tests cover the OS
default, saved choices and unavailable storage.

For visual changes, inspect light and dark themes at desktop and phone widths.
Exercise the drawer with Tab, Shift+Tab and Escape; resize while it is open;
check long tables, confirmation cancellation, conditional form sections and
populated charts. Also check empty and unavailable states. Shared static URLs
already include content versions, so updated styles do not need a manual cache
version. The HAProxy statistics frame continues to display HAProxy's own UI.

The dashboard uses two independent columns and bounded list regions. Address
filters survive data refreshes; its bans-only API view avoids reading unused
error tables. Invalidate both table caches when changing a ban. Keep the SVG
histogram fill rules and icon stroke rules: verify computed colors with real
bars and populated service rows, as empty fixtures cannot expose a lost rule.

Monitoring charts share a cursor by timestamp, including when bucket sizes or
SVG viewBox scaling differ. Hover updates the visible lines' legend readings;
leaving restores period summaries. Gaps stay missing. Pointer work is limited
to one animation frame and uses cached data. Automatic refresh pauses during
inspection or drag selection; a manual view change clears the cursor. Verify
linked cursors, null readings, touch inspection, drag zoom and full screen in
both themes, with populated charts.
