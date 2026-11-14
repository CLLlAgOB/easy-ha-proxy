# UI translations

English is the canonical source language used by templates, Python, and
JavaScript. Catalogs in this directory translate those source strings without
duplicating templates.

Large catalogs may be split into JSON fragments below a language directory,
for example `ru/backend.json`. Every fragment uses the same language code and
label; duplicate message keys are rejected.

To add a language:

1. Copy `en.json` to `<language-code>.json`.
2. Change `meta.code` so it matches the filename and change `meta.label`.
3. Add English source strings as keys and their translations as values.
4. Restart the application and run `python3 docker/app/test_i18n.py -v`.

Exact messages are preferred. Short phrase entries are also supported for
dynamic messages containing a domain, IP address, counter, or another variable
value. Longer phrases take priority over shorter ones. The English catalog is
intentionally empty because untranslated source text already falls back to
English.
