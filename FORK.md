# Fork notes

This is a fork of https://github.com/stalwartlabs/stalwart, to provide additional features we need.

## Maintenance

Maintaining a fork comes with costs, but is doable. We intend to continue to
pull in all features from the main Stalwart project.

* Do not make sweeping changes (e.g. changing formatting standards).
* Keep changes isolated, in new files, where possible.
* Add tests for new behavior to verify external changes don't cause regressions.
* Keep changes minimal, providing extensible functionality through hooks to eternal systems.
* Avoid deduplication between fork code and new functionality.
    * This helps with merge conflicts at the cost of duplication.
    * The other trade off is that when bugs are fixed in the fork, our copied code may miss out.
    * This guidance may change in the future.

### Setup

Clone this repository as `origin`, and set up the source as `upstream`.

```bash
git clone https://github.com/kagisearch/stalwart
git branch --set-upstream-to remotes/origin/main
git remote add upstream https://github.com/kagisearch/stalwart
```

### Contributing

When making a change we want to contribute to the upstream, commit your change against the merge base (find it with `git merge-base main upstream/main`), then open PRs against this fork and the upstream. Avoid rebasing after this. (In theory, this aligns the commit hashes and makes merge conflicts a little easier when [updating](#updating)).

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
