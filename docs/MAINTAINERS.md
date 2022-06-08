# go-tuf maintainer guidelines

These are expectations for the [MAINTAINERS](MAINTAINERS) of go-tuf; if you are not able to meet these requirements, please remove yourself from the list of maintainers.

## Process

Speedy communication makes contributors happy!

- You should get notifications for all activity in this repository (using the "Watch" feature) and quickly triage each issue/PR as it comes in.
  - (non-draft) PRs should have assigned reviewers.
  - Important bugs and questions should have assignees.
- If you are assigned to review a PR, please try to *acknowledge* it within one business day (no need if you are OOO).
- Please review all PRs within five business days (of course, it's okay if you're OOO).
- Please use the review checklist below.
- We should make sure there's an assigned reviewer for every PR which has passing tests.
  
Versioning:

- go-tuf releases follow [SemVer](https://semver.org/) with the following modification:
    - While go-tuf is pre-1.0, increment the minor version for any breaking changes (in SemVer, there are no guarantees about API stability).
- Releases should be tagged in this repository as usual in Go ([Publishing a module](https://go.dev/doc/modules/publishing)).

Project management:

- Try to keep issues up-to-date with status updates! 
  - Feel free to ping open issues to check on them.
  - Use the "assignee" field to indicate when you are working on an issue.
  - Use GitHub issue labels to describe the issue (exact labels are still changing, so just look through and add those that seem like a good fit).
- Before publishing a new release, there should be an associated [GitHub project](https://github.com/theupdateframework/go-tuf/projects?type=beta) to track issues.
- We will develop more process around project management after we get through the v0.4.0 release.

## Review checklist

Code review:

- [ ] Tests pass (enforced by CI).
- [ ] There should be tests for any new functionality, and regression tests for any bugs.
- [ ] Any user-facing functionality changes/additions (public APIs, command-line interface) should be documented.
- [ ] Changes should be compliant with the [TUF specification](https://theupdateframework.github.io/specification/latest/).

Pre-merge (check everything again before hitting the merge button!):

- [ ] Approvals from two different organizations.
  - This is *not* currently enforced by CI, though PRs must have at least 2 approvals.
  - This may be waived for PRs which only update docs or comments, or trivial changes to tests.
- Make sure that the PR title, commit message, and description are updated if the PR changes significantly during review.


