# Contributing Guide

We welcome and encourage community contributions to go-tuf.

Please familiarize yourself with the Contribution Guidelines before contributing.

There are many ways to help go-tuf besides contributing code:
  - Fix bugs or file issues
  - Provide feedback on the CLI experience or suggest feature enhancements.
  - Improve documentation.

## Contributing Code

Unless you are fixing a known bug, we strongly recommend discussing it with the community via a GitHub issue or Slack before getting started to ensure that your work is consistent with TUF's specification.

All contributions are made via pull request. All patches from all contributors get reviewed. See the Pull Request procedure.


## Pull Request Procedure

To make a pull request, you will need a GitHub account. See GitHub's documentation [forking](https://help.github.com/articles/fork-a-repo) and [pull requests](https://help.github.com/articles/using-pull-requests). 

Pull requests should be targeted at the `master` branch. Before creating a pull request, go through this checklist:

1. Create a feature branch off of `master` so that changes do not get mixed up.
2. If your PR adds new code, it should include tests covering the new code. If your PR fixes a bug, it should include a regression test.
3. PRs that change user-facing behavior or CLI must have associated documentation.
4. All code comments and documentation are expected to have proper English grammar and punctuation. 
5. [Rebase](http://git-scm.com/book/en/Git-Branching-Rebasing) your local changes against the `master` branch.
6. Run the full project test suite with the `go test ./...` command and confirm that it passes.
7. Run `go fmt ./...`.

When creating a PR, 

1. Accept the Developer's Certificate of Origin on all commits (see above).
2. Your PR title should be descriptive, and generally start with a subsystem prefix (ex: `client: `).
3. Your PR commit message will be used as the commit message when your PR is merged. Update this field if your PR diverges during review.
4. Your PR description should have details on what the PR does. If it fixes an existing issue, include a line like "Fixes #XXXX".

When all of the tests are passing, maintainer(s) will be assigned to review and merge the PR. 


## Communication

We use the [#tuf](https://cloud-native.slack.com/archives/C8NMD3QJ3) and [#go-tuf](https://cloud-native.slack.com/archives/C02D577GX54) channel on [CNCF Slack](https://slack.cncf.io/). You are welcome to drop in and ask questions, discuss bugs, etc.

## Pull Request review policy

* Anyone is welcome to review any PR, whether they are a maintainer or not!
* Maintainers should aim to turn around reviews within one business day.
* See [MAINTAINERS](MAINTAINERS) for the current list of maintainers.
* It is expected that two maintainers from differing organizations approve the PR before a merge. This may be waived for PRs which only update docs or comments, or trivial changes to tests.

Maintainers should:
* Make sure that the PR title, commit message, and description are updated if the PR changes significantly during review.
* Ensure that the PR guidelines above are satisfied (tests are added, documentation is added, etc).




