<p align="center">
  <img src="docs/images/logo.png" alt="rulezet-editor logo" width="200">
</p>

# rulezet-editor

A standalone, pluggable editor for detection rules (YARA first; Sigma, Suricata, Zeek, Wazuh, ... next).

It is built for [Rulezet](https://github.com/ngsoti/rulezet-core) but is not tied to it: the same
editor runs in any web page, in MISP, in an internal SOC tool or in a VS Code webview.

> Status: 0.1.0, first working version with the YARA language pack.
> Architecture: [docs/design.md](docs/design.md). How it works inside, step by step: [docs/how-it-works.md](docs/how-it-works.md).

## Try it

```bash
npm install
npm run dev            # http://127.0.0.1:5173/
```

The playground forwards `/api` to a Rulezet instance (default `http://127.0.0.1:7009`) so rules are
also checked by the real YARA compiler and rule names are looked up on Rulezet:

```bash
RULEZET_URL=https://rulezet.org npm run dev
```

## What the YARA pack does

| Area | Features |
|---|---|
| Highlighting | keywords, sections, `$strings`, modifiers, modules, hex strings (bytes, wildcards, jumps), regexes, tags, comments |
| Completion | rule templates, sections, meta keys, string snippets, modifiers valid for the string kind, `$` / `#` / `@` / `!` identifiers, `$prefix*` sets, module members (`pe.sections[0].name`), modules (adds the `import` for you), rules defined above, rules that exist on Rulezet |
| Diagnostics while typing | syntax errors (every rule keeps being checked after one breaks), undefined / unused / duplicate strings, wildcards that match nothing, module used without import, unknown module member, unused import, rule used before its definition, unknown rule, duplicate rule / tag, invalid modifiers and combinations, `xor` range, base64 alphabet, hex string checks (single digit, bad characters, jumps), text escapes, deprecated `entrypoint`, missing meta, performance hints (short atoms, leading wildcards, `.*`) |
| Quick fixes | add the import, add the meta, use or remove an unused string, fix a typo in a string name, replace `entrypoint`, close a rule, insert a rule from Rulezet |
| Server checks | the whole document is compiled by the host (Rulezet: the same check as rule creation), errors mapped to their line |
| Navigation | hover docs (keywords, modules, strings with byte length / hex, rules, rules on Rulezet), go to definition (F12, Ctrl+Click), highlight of every occurrence, rename (F2) |
| Several rules per document | rules panel with status per rule, strings and condition, filter, copy one rule |
| Formatting | Shift+Alt+F: one layout, aligned `=`, comments kept, rules with errors left untouched |
| Editor | folding per rule and section, multi-cursor, find / replace, command palette (Ctrl+Shift+P), light / dark / auto theme, full screen, drafts kept in the browser, English / French UI |

## Use it in a page

```html
<link rel="stylesheet" href="dist/rulezet-editor.css">
<div id="editor" style="height:520px"></div>
<script type="module">
  imp