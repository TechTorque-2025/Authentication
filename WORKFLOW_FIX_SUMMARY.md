# CI/CD Workflow Fix Summary

## Problem Identified

The "Update K8s Manifest" workflow was executing **before** the Docker image was built, causing manifest updates with non-existent image tags.

### Root Cause

The original `build.yaml` had two jobs:
1. `build-test` - Always runs
2. `build-and-push-docker` - Only runs on push to main/dev (conditional)

GitHub Actions' `workflow_run` trigger fires when the workflow **completes**, which happened after `build-test` finished, even though `build-and-push-docker` was still running or skipped.

## Solution Implemented

### 1. Split Workflows by Purpose

**Before:** Single `build.yaml` tried to handle both PR validation and Docker builds

**After:** Three focused workflows:

#### [build-test.yaml](/.github/workflows/build-test.yaml)
- **Trigger:** Pull requests to main/dev
- **Purpose:** Validate builds before merge
- **Actions:** Maven build only
- **Duration:** ~30s

#### [build.yaml](/.github/workflows/build.yaml) (renamed to "Build and Push Docker Image")
- **Trigger:** Push to main/dev branches only
- **Purpose:** Build and publish Docker images
- **Actions:** Maven build + Docker build + Push to GHCR
- **Output:** Image tagged as `{branch}-{sha}` (e.g., `dev-0f42d3b`)

#### [update-manifest.yaml](/.github/workflows/update-manifest.yaml)
- **Trigger:** After "Build and Push Docker Image" completes successfully
- **Purpose:** Update k8s-config repo with new image tag
- **Actions:**
  - Checkout k8s-config
  - Update deployment YAML with new image tag
  - Commit and push changes
  - ArgoCD auto-syncs from there

### 2. Workflow Execution Flow

```
┌─────────────────────────────────────────────────────────────┐
│                     PR to main/dev                          │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
            ┌──────────────────────┐
            │  build-test.yaml     │
            │  (PR validation)     │
            └──────────────────────┘
                       │
                       ▼
                   ✅ Merge
                       │
                       ▼
┌──────────────────────────────────────────────────────────────┐
│                   Push to main/dev                           │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       ▼
            ┌──────────────────────────┐
            │  build.yaml              │
            │  1. Maven build          │
            │  2. Docker build         │
            │  3. Push to GHCR         │
            └──────────┬───────────────┘
                       │
                       │ (workflow_run trigger)
                       ▼
            ┌──────────────────────────┐
            │  update-manifest.yaml    │
            │  1. Checkout k8s-config  │
            │  2. Update image tag     │
            │  3. Git commit & push    │
            └──────────┬───────────────┘
                       │
                       ▼
            ┌──────────────────────────┐
            │  ArgoCD Auto-Sync        │
            │  (deploys to cluster)    │
            └──────────────────────────┘
```

## Key Changes

### build-test.yaml (NEW)
```yaml
name: Build and Test
on:
  pull_request:
    branches: ['main', 'dev']
```
- Simple PR validation
- No Docker build
- Fast feedback

### build.yaml (UPDATED)
```yaml
name: Build and Push Docker Image
on:
  push:
    branches: ['main', 'dev']
```
- Single job: `build-and-push`
- No conditionals - always runs when triggered
- Predictable completion

### update-manifest.yaml (UPDATED)
```yaml
on:
  workflow_run:
    workflows: ["Build and Push Docker Image"]  # Changed from "Build and Package Service"
    types: [completed]
```
- Now triggers on correct workflow name
- Only runs after Docker image is successfully built and pushed

## Benefits

1. **Correct Execution Order:** Manifest only updates after image exists
2. **Faster PR Feedback:** Build-test is lightweight and fast
3. **Clear Separation of Concerns:** Each workflow has one job
4. **Easier Debugging:** Workflow names and purposes are clear
5. **No Race Conditions:** Sequential execution guaranteed

## Testing

To test the complete pipeline:

1. **Create a feature branch:**
   ```bash
   git checkout -b test/cicd-pipeline
   ```

2. **Make a commit (or empty commit):**
   ```bash
   git commit --allow-empty -m "test: verify CI/CD pipeline"
   ```

3. **Push and create PR:**
   ```bash
   git push origin test/cicd-pipeline
   gh pr create --base dev --title "Test CI/CD Pipeline"
   ```

4. **Expected behavior:**
   - `build-test.yaml` runs immediately
   - Shows build success in PR checks

5. **After merge to dev:**
   - `build.yaml` runs (builds Docker image)
   - `update-manifest.yaml` runs (updates k8s-config)
   - ArgoCD syncs changes to cluster

## Files Modified

- ✅ Created: `.github/workflows/build-test.yaml`
- ✅ Updated: `.github/workflows/build.yaml`
- ✅ Updated: `.github/workflows/update-manifest.yaml`
- ℹ️  Kept: `.github/workflows/deploy.yaml.old` (for reference)

## Next Steps

To roll out this fix to other microservices:

1. Copy the three workflow files
2. Update service-specific values:
   - Maven path (e.g., `time-logging-service/pom.xml`)
   - Image name (e.g., `timelogging_service`)
   - Deployment file (e.g., `timelogging-deployment.yaml`)
3. Test with a PR to dev branch
4. Monitor GitHub Actions for correct execution order

---

**Date:** 2025-11-15
**Status:** ✅ Complete
**Affected Service:** Authentication
