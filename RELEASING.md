# Releasing a new version of `go-tpm-tools`

This repository contains multiple Go modules, so care is needed when creating a
new version. Be sure to follow these steps as it's very easy to accidentally
cut a release (as GitHub doesn't have sufficiently advanced
[tag protections](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/configuring-tag-protection-rules)).

## Create the main release PR

Create a standalone PR titled "Release vX.Y.Z" against the `master` branch. This
PR should (ideally) be an empty commit, but might contain some minor changes if
we want to get them in for a specific release. You can create an empty commit
by running:
```
git commit --allow-empty
```

The description of the PR should just be the release notes that we want to
publish in the GitHub Release. The notes should just have one-line summaries
of the PRs in the release. Trivial PRs can be omitted and related PRs can be
combined in a single line. It should have the following subsections:
  - "Breaking Changes" (backwards-incompatible changes to the package API)
  - "New Features" (backwards-compatible changes to the package API)
  - "Bug Fixes" (fixes to any particular issues)
  - "Other Changes" (non-breaking code changes or Doc/CI updates)

Sections can be omitted if there wouldn't be any PRs under them. The
[`v0.3.2` release notes](https://github.com/google/go-tpm-tools/releases/tag/v0.3.2)
are a good example. We don't need to specifically mention who wrote what PR or
link to the "Full Changelog". Users can just look this stuff up on GitHub on
their own.

This commit _should not_ change the version numbers in [`go.work`](go.work),
[`cmd/go.mod`](cmd/go.mod), or [`launcher/go.mod`](launcher/go.mod). When
reviewing the PR, the reviewers and author should decide if the release
will be a major, minor, or patch release. Note that the PR should only consist
of a single commit and be "squashed" instead of "merged".

## Tag the releases

After the new release is in the `master` branch, we need to create git tags so
that the Go version system can find the releases. Generally the author of the
PR should do this.

Tagging can be done via the GitHub Web UI. On the
[Releases Page](https://github.com/google/go-tpm-tools/releases),
click [Draft a New Release](https://github.com/google/go-tpm-tools/releases/new).
In that draft, create the git tag corresponding to your release, and copy the
approved release notes into the description.

Check that the preview of the release notes looks good, and click
"Publish release". The release and tag should now be visible on GitHub. 

## Follow-up Submodule update PR

After the main release has been merged and tagged, we need to update the go.mod
files in the various submodules. First, you should update the version number in:
  - [`go.work`](go.work)
  - [`cmd/go.mod`](cmd/go.mod)
  - [`launcher/go.mod`](launcher/go.mod)

Next, we cleanup the modules by running:
  - run `go mod tidy` in each module directory
  - run `go work sync` in the root directory
  - this requires Go 1.20 or later

Finally, create a PR with the title "Submodule update for vX.Y.Z". This PR
doesn't need a description. The reviewers should just check that the above
steps were done. Note that the PR should only consist
of a single commit and be "squashed" instead of "merged".

## Tagging the submodules

The submodules must be tagged separately from the main library release. This
is best done on the git command line. After the Submodule update PR has been
merged, checkout the repo and check that your `HEAD` is on the commit for the
submodule update PR on the `master` branch. This _should not_  be normal release
commit `vX.Y.Z`, but a later commit. Then, run the following command:
```
git tag "cmd/vX.Y.Z" && git tag "launcher/vX.Y.Z"
```
replacing `vX.Y.Z` with the actual version number.

Finally, double check that you've tagged the correct commit, and then push the
tags to the `master` branch by running:
```
git push origin "cmd/vX.Y.Z" "launcher/vX.Y.Z"
```

The tags should then be visible at https://github.com/google/go-tpm-tools/tags

## (Googlers only) sync code back into google3

Follow the directions at http://go/thirdpartygo#updating-imported-code to import
the three modules back into google3. You will need to run the import script for
each module. It's fine for the imports for all the modules to be in one CL.
