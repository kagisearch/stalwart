# Fork notes

This is a fork of https://github.com/stalwartlabs/stalwart, to provide additional features we need.

## Maintenance

Maintaining a fork comes with costs, but is doable. We intend to continue to
pull in all features from the main Stalwart project.

* Do not make sweeping changes (e.g. changing formatting standards).
* Keep changes isolated, in new files, where possible.
* Add tests for new behavior to verify external changes don't cause regressions.
* Keep changes minimal, providing extensible functionality through hooks to eternal systems.

### Setup

Clone this repository as `origin`, and set up the source as `upstream`.

```bash
git clone https://github.com/kagisearch/stalwart
git branch --set-upstream-to remotes/origin/main
git remote add upstream https://github.com/kagisearch/stalwart
```

### Updating

Upgrade to a specific, released version of stalwart only.

```bash
git fetch --tags upstream
git merge tags/v0.13.3
```

In certain cases, it's worth aborting a merge and refactoring to make conflicts easier to resolve (e.g. a new file is added with the same name as a file the fork added).

### Build

Our custom build looks like:

```bash
cargo build --release -p stalwart --no-default-features --features postgres
```
