"""Generate branch protection recommendations."""

from __future__ import annotations


def generate_branch_protection_guide() -> str:
    """Generate a guide for setting up branch protection rules.

    Reference: https://best.openssf.org/SCM-BestPractices/
    """
    return """# Branch Protection Setup Guide

Follow the [OpenSSF SCM Best Practices Guide](https://best.openssf.org/SCM-BestPractices/)
to configure branch protection for your repository.

## Recommended Settings for `main` / `master` branch

### Required (OpenSSF Scorecard checks these)

- [x] **Require pull request reviews before merging**
  - Require at least 1 approving review
  - Dismiss stale pull request approvals when new commits are pushed
  - Require review from Code Owners

- [x] **Require status checks to pass before merging**
  - Require branches to be up to date before merging
  - Add your CI/test workflow as a required check

- [x] **Require signed commits** (if using Sigstore/GPG)

- [x] **Do not allow force pushes**

- [x] **Do not allow deletions**

### Recommended

- [x] **Require conversation resolution before merging**
- [x] **Require linear history** (encourages rebase/squash merges)
- [x] **Include administrators** in branch protection rules

## How to Set Up

### Via GitHub UI
1. Go to **Settings** > **Branches**
2. Click **Add branch protection rule**
3. Set **Branch name pattern** to `main` (or `master`)
4. Enable the settings listed above
5. Click **Create** / **Save changes**

### Via GitHub CLI
```bash
gh api repos/{owner}/{repo}/branches/main/protection \\
  --method PUT \\
  --field required_pull_request_reviews='{"required_approving_review_count":1,"dismiss_stale_reviews":true}' \\
  --field required_status_checks='{"strict":true,"contexts":["ci"]}' \\
  --field enforce_admins=true \\
  --field restrictions=null \\
  --field allow_force_pushes=false \\
  --field allow_deletions=false
```

## Verification

After setting up branch protection, you can verify your configuration
using [OpenSSF Scorecard](https://scorecard.dev/):

```bash
scorecard --repo=github.com/OWNER/REPO --checks=Branch-Protection
```

Or check the **Branch-Protection** check on your
[Scorecard results page](https://scorecard.dev/viewer/).
"""
