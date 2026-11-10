# fixornix

Fix it or nix it. fixornix reads your repo's open Dependabot alerts and tells you what to do with each one.

```
$ npx fixornix
owner/app: 3 open alerts

Fix now (1)
  #12 @sveltejs/kit [low] SvelteKit : XSS via untrusted cache-control header in prerendered page
    @sveltejs/kit 2.70.3 needs a bigger upgrade to reach 3.0.0
    -> change @sveltejs/kit in your package.json from ^2.65.1 to ^3.0.0, then upgrade @sveltejs/adapter-static to 4.0.1

Development only, no fix: check, then dismiss (1)
  #7 deepmerge [low] deepmerge mergeObject() allows prototype poisoning of returned objects
    deepmerge 4.3.1 is only used in development, and no fixed version exists yet
    -> dismiss as "tolerable risk" if it isn't bundled into what you ship

Not in your build: safe to dismiss (1)
  #5 glib [medium] Unsoundness in `Iterator` and `DoubleEndedIterator` impls for `glib::VariantStrIter`
    glib 0.18.5 isn't compiled for your targets (x86_64-pc-windows-msvc); glib 0.18.5 can't move to 0.20.0: gtk v0.18.2 requires an older version
    -> dismiss as "not used"
```

Each alert lands in one group: **fix now**, **blocked** by another package, **no fix yet**, **development only**,
or **not in your build**.

## Usage

Run it in your repo with Node.js 18+. It uses your `gh` login or a `GITHUB_TOKEN` that can read Dependabot alerts.

```
npx fixornix [--target x86_64-pc-windows-msvc] [--markdown report.md] [--json] [--dismiss --yes]
```

- `--target`: the Rust targets you ship (default: this machine's)
- `--markdown`: also write the report as Markdown, e.g. to `$GITHUB_STEP_SUMMARY`
- `--dismiss --yes`: dismiss the "not in your build" alerts on GitHub, with the reason as a comment

Full checks for npm, yarn, pnpm and Cargo lockfiles. Other ecosystems use GitHub's data only.

## License

MIT
