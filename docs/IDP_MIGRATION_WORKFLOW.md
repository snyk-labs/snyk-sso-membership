# Snyk IdP Migration Workflow Guide

This guide provides step-by-step instructions for migrating Snyk users from one Identity Provider (IdP) to another while preserving all their Group and Organization memberships.

## Table of Contents

- [Overview](#overview)
- [Use Case](#use-case)
- [Prerequisites](#prerequisites)
- [The 3-Step Workflow](#the-3-step-workflow)
  - [Step 1: Export Users and Memberships](#step-1-export-users-and-memberships)
  - [Step 2: Assign Memberships to New IdP Users](#step-2-assign-memberships-to-new-idp-users)
  - [Step 3: Delete Old Memberships](#step-3-delete-old-memberships)
- [Advanced Scenarios](#advanced-scenarios)
- [Troubleshooting](#troubleshooting)
- [Best Practices](#best-practices)

## Overview

When migrating from one IdP to another (e.g., from Okta to Azure AD), you'll have:
- **Old users** on the old SSO connection with existing memberships
- **New users** on the new SSO connection (same email addresses but new user IDs)

This workflow allows you to:
1. Export all membership data from old users
2. Apply those memberships to corresponding new users
3. Clean up old users' memberships without deleting accounts

## Use Case

**Scenario**: You're changing your IdP from `old-idp` to `new-idp`, but users will have the same email addresses.

**Challenge**: Users exist on **two different SSO connections simultaneously** with different user IDs. You need to transfer memberships without:
- Deleting user accounts
- Losing organization memberships
- Manual re-invitation of thousands of users

**Solution**: Use the JSON-based workflow to automate the migration.

## Prerequisites

1. **Snyk Service Account** with Group Admin role
2. **Environment Variable** set:
   ```bash
   export SNYK_TOKEN=<your_snyk_api_token>
   ```
3. **Both IdPs configured** in Snyk (old and new SSO connections)
4. **Users provisioned** on the new IdP (they exist but have no memberships yet)

## The 3-Step Workflow

### Step 1: Export Users and Memberships

Export users and their complete membership data from the **old IdP group(s)**. You can pass multiple domains as a comma-separated list (e.g. `--domain=robsworld.com,Robsworld.com`) to include users from all of them.

#### Single Group Export

```bash
snyk-sso-membership generate-memberships-json <oldGroupID> \
  --domain=robsworld.com \
  > users_with_memberships.json
```

#### Multiple Groups Export (Recommended for Large Organizations)

If your users span multiple Snyk groups, consolidate them in one export:

```bash
snyk-sso-membership generate-memberships-json \
  --groups=oldGroupID1,oldGroupID2,oldGroupID3 \
  --domain=robsworld.com \
  > users_with_memberships.json
```

**What this does:**
- Fetches all SSO users from specified group(s)
- Retrieves their Group memberships
- Retrieves their Organization memberships with roles
- Deduplicates users by email across groups
- Merges all memberships into a single JSON file

**Output:** `users_with_memberships.json` containing:
```json
{
  "users": [
    {
      "id": "old-user-id",
      "username": "john.doe@robsworld.com",
      "email": "john.doe@robsworld.com",
      "name": "John Doe",
      "active": true,
      "group_memberships": [
        {
          "membership_id": "...",
          "id": "group-uuid",
          "name": "Customer Name",
          "role_id": "...",
          "role_name": "Group Member"
        }
      ],
      "org_memberships": [
        {
          "membership_id": "...",
          "id": "org-uuid",
          "name": "Production Org",
          "role_id": "...",
          "role_name": "Org Admin",
          "org_id": "org-uuid",
          "role": "ADMIN"
        }
      ]
    }
  ]
}
```

**Scaling:** This command handles thousands of users automatically with:
- Built-in pagination (100 users per page)
- Rate limiting (1620 requests/minute)
- Automatic retry on failures

---

### Step 2: Assign Memberships to New IdP Users

Apply the exported memberships to users in the **new IdP group**.

```bash
snyk-sso-membership assign-memberships-from-json <newIdPGroupID> \
  --input=users_with_memberships.json
```

**What this does:**
1. Fetches all SSO users from the **new IdP group** (they have NEW user IDs)
2. Matches each user to the JSON by email address
3. For each match, creates:
   - Group memberships (using group IDs from JSON)
   - Organization memberships (using org IDs from JSON)
4. Uses the **NEW user ID** to create the memberships

**Key Points:**
- The command uses the **new user IDs** from `<newIdPGroupID>`
- Group and Org IDs come from the JSON (preserves exact structure)
- Idempotent: safe to re-run if it fails partway through
- Ignores 409 conflicts (membership already exists)

**Expected Output:**
```
INFO  Found 3 users in group b47373d1-6cac-4790-857d-3530982b6369
INFO  Found 3 users in JSON file
INFO  Matched user: john.doe@robsworld.com, applying memberships
INFO  Created/updated group membership for user john.doe@robsworld.com in group Customer Name with role Group Member
INFO  Created/updated org membership for user john.doe@robsworld.com in org Production Org with role Org Admin
...
```

**Flags:**
- `--input`: Path to JSON file (required)
- `--matchByUserName`: Match by username instead of email (optional)

---

### Step 3: Delete Old Memberships

Remove memberships from the **old IdP users** without deleting their accounts.

```bash
snyk-sso-membership delete-memberships-from-json \
  --input=users_with_memberships.json
```

**What this does:**
1. Reads the JSON file
2. For each user, deletes:
   - All Organization memberships (using org IDs from JSON)
   - All Group memberships (using group IDs from JSON)
3. **Does NOT delete user accounts**

**Key Points:**
- No groupID argument needed - group IDs are in the JSON
- Works across multiple groups automatically
- Leaves users in the system but with no memberships
- Safe for multi-group scenarios

**Expected Output:**
```
INFO  Processing 3 users from JSON file
INFO  Deleted org membership in org Production Org for user john.doe@robsworld.com
INFO  Deleted group membership in group Customer Name for user john.doe@robsworld.com
...
INFO  Completed deleting memberships from JSON
```

---

## Advanced Scenarios

### Scenario 1: Large Enterprise with Many Groups

**Situation:** You have 10+ Snyk groups and thousands of users.

**Solution:**
```bash
# Step 1: Export all groups at once
snyk-sso-membership generate-memberships-json \
  --groups=group1,group2,group3,group4,group5,group6,group7,group8,group9,group10 \
  --domain=company.com \
  > all_users.json

# Step 2: Assign to new IdP group
snyk-sso-membership assign-memberships-from-json <newIdPGroupID> \
  --input=all_users.json

# Step 3: Clean up old memberships across all groups
snyk-sso-membership delete-memberships-from-json \
  --input=all_users.json
```

The tool automatically:
- Paginates through all users
- Rate limits requests
- Deduplicates users across groups
- Handles all group IDs correctly

### Scenario 2: Selective User Migration

**Situation:** You want to migrate only specific users, not all users in a domain.

**Solution:**

1. Create a CSV with user emails:
   ```csv
   john.doe@company.com
   jane.smith@company.com
   bob.jones@company.com
   ```

2. Export only those users:
   ```bash
   snyk-sso-membership generate-memberships-json \
     --groups=group1,group2 \
     --csvFilePath=./users_to_migrate.csv \
     > selected_users.json
   ```

3. Continue with steps 2 and 3 as normal


### Scenario 3: Dry Run / Testing

Before running the migration on production:

1. **Export** from production (read-only):
   ```bash
   generate-memberships-json --groups=prod1,prod2 > users.json
   ```

2. **Review the JSON** to verify it contains expected users and memberships

3. **Test on a small group** first:
   ```bash
   # Test with single test group
   assign-memberships-from-json <testGroupID> --input=users.json
   ```

4. **Verify** in Snyk UI that memberships were created correctly

5. **Roll back if needed** (delete test memberships):
   ```bash
   delete-memberships-from-json --input=users.json
   ```

---

## Troubleshooting

### Issue: "No matching JSON entry for user"

**Cause:** User email in new IdP doesn't match email in JSON.

**Solution:**
- Verify emails match exactly between old and new IdP
- Check if you should use `--matchByUserName` instead
- Review the JSON file to confirm user emails


### Issue: "Failed to create group membership: 409"

**Cause:** Membership already exists (this is normal and safe).

**Solution:** The tool automatically ignores 409 conflicts. This just means the membership was already created (e.g., from a previous run).

### Issue: Processing is slow with thousands of users

**Cause:** Rate limiting is protecting the API.

**Solution:** This is expected and automatic. The tool:
- Respects Snyk API rate limits (1620 req/min for REST API)
- Will complete eventually - be patient with large datasets
- Check log files for progress

### Issue: Need to verify what was changed

**Solution:** Check the log file:
```bash
ls -t snyk-sso-membership_run_*.log | head -1 | xargs cat
```

Run with `--debug` for detailed output:
```bash
snyk-sso-membership assign-memberships-from-json <groupID> \
  --input=users.json \
  --debug
```

---

## Best Practices

### 1. Always Export First

Before making any changes, export the current state:
```bash
generate-memberships-json --groups=all,your,groups > backup_$(date +%Y%m%d).json
```

### 2. Validate the JSON

After exporting, review the JSON file:
- Check user count: `jq '.users | length' users.json`
- Check a sample user: `jq '.users[0]' users.json`
- Verify org memberships: `jq '.users[0].org_memberships | length' users.json`

### 3. Test on a Small Group First

Don't start with your entire production environment:
1. Pick a test group with 5-10 users
2. Run the full 3-step workflow
3. Verify in Snyk UI
4. If successful, proceed with production groups

### 4. Keep Log Files

The tool creates timestamped log files:
```
snyk-sso-membership_run_20251010152030.log
```

Keep these for:
- Audit trail
- Troubleshooting
- Verification of what was changed

### 5. Coordinate with Users

**Note:** The IdP migration process:
- Does NOT send email notifications (only membership changes)
- Does NOT interrupt user access (users remain active)
- Can be done while users are working

However, communicate the migration timeline to avoid confusion.

### 6. Handle Failures Gracefully

If Step 2 (assign) fails partway through:
- Review the log file to see which users succeeded
- Re-run the command (it's idempotent)
- The tool will skip users that already have memberships (409 errors)

### 7. Verify Before Deleting

Before running Step 3 (delete old memberships):
1. Verify new users have correct memberships in Snyk UI
2. Test that new users can log in successfully
3. Confirm all critical organization access is maintained

---

## Complete Example Walkthrough

Here's a real-world example migrating from an old Okta IdP to a new Azure AD IdP:

### Setup

```bash
# Set your Snyk API token
export SNYK_TOKEN=<your_group_admin_token>

# Navigate to your working directory
cd /path/to/migration

# Identify your group IDs (from Snyk UI)
OLD_GROUP_1=a1b2c3d4-e5f6-7890-abcd-ef1234567890
OLD_GROUP_2=b2c3d4e5-f6g7-8901-bcde-f12345678901
NEW_GROUP=c3d4e5f6-g7h8-9012-cdef-123456789012
NEW_GROUPS=c3d4e5f6-g7h8-9012-cdef-123456789012,b2c3d4e5-f6g7-8901-bcde-f12345678901,a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

### Step 1: Export from Old IdP

```bash
# Export all users from both old groups
snyk-sso-membership generate-memberships-json \
  --groups=${OLD_GROUP_1},${OLD_GROUP_2} \
  --domain=company.com \
  > migration_export_$(date +%Y%m%d).json

# Example output:
# INFO  Processing 2 group(s)
# INFO  Fetching users from group: a1b2c3d4-e5f6-7890-abcd-ef1234567890
# INFO  Found 150 users in group a1b2c3d4-e5f6-7890-abcd-ef1234567890
# INFO  Fetching users from group: b2c3d4e5-f6g7-8901-bcde-f12345678901
# INFO  Found 200 users in group b2c3d4e5-f6g7-8901-bcde-f12345678901
# INFO  Successfully generated membership data for 325 users across 2 group(s)
```

**Verify the export:**
```bash
# Count users
jq '.users | length' migration_export_$(date +%Y%m%d).json

# Check a sample user
jq '.users[0] | {email, org_count: (.org_memberships | length), group_count: (.group_memberships | length)}' migration_export_$(date +%Y%m%d).json
```

### Step 2: Assign to New IdP

**IMPORTANT:** Before running this step:
- Ensure users are provisioned on the new IdP
- Verify they can log in to Snyk with the new IdP
- Test with a small subset first

```bash
# Assign memberships to users in the new IdP group
snyk-sso-membership assign-memberships-from-json ${NEW_GROUP} \
  --input=migration_export_$(date +%Y%m%d).json

# Example output:
# INFO  Found 325 users in group c3d4e5f6-g7h8-9012-cdef-123456789012
# INFO  Found 325 users in JSON file
# INFO  Matched user: john.doe@company.com, applying memberships
# INFO  Created/updated group membership for user john.doe@company.com in group Customer Name with role Group Member
# INFO  Created/updated org membership for user john.doe@company.com in org Production Org with role Org Admin
# ... (continues for all users)
```

**Verify assignments:**
- Log in as a test user with the new IdP
- Check they have access to expected organizations
- Verify roles are correct in Snyk UI

### Step 3: Delete Old Memberships

**IMPORTANT:** Only run this after verifying Step 2 succeeded!

```bash
# Delete old users' memberships (does NOT delete accounts)
snyk-sso-membership delete-memberships-from-json \
  --input=migration_export_$(date +%Y%m%d).json

# Example output:
# INFO  Processing 325 users from JSON file
# INFO  Deleted org membership in org Production Org for user john.doe@company.com
# INFO  Deleted group membership in group Customer Name for user john.doe@company.com
# ... (continues for all users)
# INFO  Completed deleting memberships from JSON
```

**Result:**
- Old users remain in the system but have no memberships
- New users have all the memberships from the old users
- You can now deactivate the old SSO connection if needed

---

## Advanced Scenarios

### Phased Migration

If you want to migrate users in batches:

```bash
# Phase 1: Export specific users (batch 1)
cat > batch1_users.csv << EOF
user1@company.com
user2@company.com
user3@company.com
EOF

snyk-sso-membership generate-memberships-json <oldGroupID> \
  --csvFilePath=batch1_users.csv \
  > batch1_export.json

# Assign and delete for batch 1
snyk-sso-membership assign-memberships-from-json <newGroupID> --input=batch1_export.json
snyk-sso-membership delete-memberships-from-json --input=batch1_export.json

# Repeat for batch 2, 3, etc.
```

### Rollback Strategy

If you need to roll back Step 2 (undo membership assignments):

```bash
# You can delete the new memberships using the same JSON
# (This removes memberships from new IdP users)
snyk-sso-membership delete-memberships-from-json --input=users_with_memberships.json

# Then re-assign back to old users if needed
snyk-sso-membership assign-memberships-from-json <oldGroupID> --input=users_with_memberships.json
```

### Cross-Group Membership Preservation

The multi-group export automatically handles users who are members of multiple groups:

```bash
# User belongs to both GroupA and GroupB
# Export preserves memberships from both
generate-memberships-json --groups=groupA,groupB > users.json

# Result: JSON contains:
# - Group membership for GroupA
# - Group membership for GroupB  
# - All org memberships from both groups (deduplicated)
```

---

## Troubleshooting

### Debug Mode

Run any command with `--debug` for detailed logging:

```bash
snyk-sso-membership assign-memberships-from-json <groupID> \
  --input=users.json \
  --debug 2>&1 | tee debug_output.log
```

### Common Issues and Solutions

| Issue | Cause | Solution |
|-------|-------|----------|
| No users matched | Email mismatch between IdPs | Verify emails are identical; try `--matchByUserName` |
| 400 errors | Incorrect API request format | Update to latest version with fixed role types |
| 409 errors (conflicts) | Membership already exists | Safe to ignore - means it's already created |
| 404 errors | Membership/user not found | Verify IDs in JSON are still valid |
| Rate limit errors | Too many requests | Built-in rate limiting; wait and retry |

### Verification Queries

```bash
# Count users by group in JSON
jq '.users | group_by(.group_memberships[0].id) | map({group: .[0].group_memberships[0].name, count: length})' users.json

# List all organizations in the export
jq '[.users[].org_memberships[].name] | unique | sort' users.json

# Find a specific user
jq '.users[] | select(.email == "john.doe@company.com")' users.json
```

---

## Best Practices

### Before Migration

- [ ] Backup: Export current state and save the JSON
- [ ] Document: Note all group IDs and SSO connection names
- [ ] Test: Run on a test group with 5-10 users first
- [ ] Communicate: Inform users of the migration timeline

### During Migration

- [ ] Monitor: Watch log files for errors
- [ ] Verify: Spot-check users in Snyk UI after Step 2
- [ ] Patience: Allow time for rate limiting with large datasets
- [ ] Keep logs: Save all log files for audit trail

### After Migration

- [ ] Verify: Test user login with new IdP
- [ ] Confirm: Check organization access for critical users
- [ ] Clean up: Run Step 3 to remove old memberships
- [ ] Document: Record what was migrated and when
- [ ] Deactivate: Consider deactivating old SSO connection after testing period

---

## Workflow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│ Step 1: Export                                                  │
│                                                                 │
│  OLD IdP Groups → generate-memberships-json → users.json        │
│  (group1, group2, group3)                                       │
│                                                                 │
│  • Fetches all users                                            │
│  • Gets all memberships                                         │
│  • Consolidates & deduplicates                                  │
│  • Outputs complete JSON                                        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 2: Assign                                                  │
│                                                                 │
│  NEW IdP Group + users.json → assign-memberships-from-json      │
│                                                                 │
│  • Fetches NEW users (with new user IDs)                        │
│  • Matches by email to JSON                                     │
│  • Creates memberships using:                                   │
│    - NEW user IDs                                               │
│    - Group/Org/Role IDs from JSON                               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Step 3: Delete                                                  │
│                                                                 │
│  users.json → delete-memberships-from-json                      │
│                                                                 │
│  • Reads old user/membership IDs from JSON                      │
│  • Deletes group memberships (across all groups)                │
│  • Deletes org memberships                                      │
│  • Leaves user accounts intact                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    ✅ Migration Complete!
```

---

## Support

For issues or questions:
- Check the main [README.md](../README.md) for general tool usage
- Review log files in `snyk-sso-membership_run_*.log`
- Open an issue on GitHub with:
  - Command you ran
  - Relevant log output
  - Sanitized JSON sample (remove sensitive data)

---

## Quick Reference

```bash
# Full workflow - single line commands
snyk-sso-membership generate-memberships-json --groups=old1,old2 --domain=company.com > users.json
snyk-sso-membership assign-memberships-from-json <newGroupID> --input=users.json
snyk-sso-membership delete-memberships-from-json --input=users.json

# With verification between steps
snyk-sso-membership generate-memberships-json --groups=old1,old2 --domain=company.com > users.json && \
  jq '.users | length' users.json && \
  echo "Review the JSON, then run Step 2"

# Check the most recent log file
ls -t snyk-sso-membership_run_*.log | head -1 | xargs tail -n 50
```

