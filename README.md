![Snyk logo](https://snyk.io/style/asset/logo/snyk-print.svg)

# Snyk SSO Membership Tool

This command-line tool helps Snyk Group Administrators manage user memberships during a Single Sign-On (SSO) domain migration. It simplifies migrating Group and Organization memberships for users represented across two different email domains on an SSO connection.

For example, migrating a user from:

- `user@source.com` to `user@destination.com` (by `email` property)
- `user@source.com` to `user` (by `username` property)

## Table of Contents

- [Key Features](#key-features)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Build](#build)
- [Usage](#usage)
  - [`sync`](#sync-synchronizing-user-memberships)
  - [`get-users`](#get-users-getting-sso-users)
  - [`delete-users`](#delete-users-deleting-sso-users)
- [IdP Migration Workflow](#idp-migration-workflow)
- [How Snyk User Profiles are Matched](#how-snyk-user-profiles-are-matched)
- [⚠️ Important Behavior](#️-important-behavior)
- [Logging](#logging)
- [License](#license)

## Key Features

*   **Synchronize Memberships**: Copy a user's Snyk Group and Organization roles from a source account to a destination account.
*   **Delete Users**: Bulk-delete Snyk SSO users from a specific domain.
*   **Flexible User Matching**: Match Snyk users by email, username, or the local-part of an email address to accommodate complex identity provider (IdP) setups.
*   **IdP Migration Workflow**: Export memberships as JSON, assign them to users in a new IdP, and clean up old memberships without deleting user accounts.

## Getting Started

### Prerequisites

You will need a Snyk Service Account API token with the **Group Admin** role. Export it as an environment variable:

```bash
export SNYK_TOKEN=<your_snyk_api_token>
```

### Installation

Download the appropriate binary for your system from the latest [GitHub release](https://github.com/snyk/snyk-sso-membership/releases).

### Build

To build the `snyk-sso-membership` executable from source:

```bash
make build
```

## Usage

The tool provides the following commands: `sync`, `get-users`, `delete-users`, and specialized IdP migration commands (see [IdP Migration Workflow](#idp-migration-workflow)).

### `sync`: Synchronizing User Memberships

This command synchronizes Group and Organization memberships from users on a source domain to users on a destination domain.

> [!WARNING]
> The `sync` command performs a **full synchronization**. The destination user's list of Organization memberships will become an exact mirror of the source user's. Any memberships the destination user had that the source user did not will be **deleted**.

#### Sync All Users in a Group

This command finds pairs of users across two domains who share the same local-part (username) in their email address.

```bash
snyk-sso-membership sync <groupID> --domain=source.com --ssoDomain=destination.com
```

#### Sync a Selective List of Users

You can provide a CSV file containing a list of source user emails to sync.

**Example `users.csv`:**
```csv
user1@source.com
user2@source.com
```

**Command:**
```bash
snyk-sso-membership sync <groupID> --domain=source.com --ssoDomain=destination.com --csvFilePath="./users.csv"
```

#### `sync` Command Options

| Option | Description |
| --- | --- |
| `--domain` | The source domain(s) to match users from. One domain or comma-separated list (e.g. `robsworld.com,Robsworld.com`). |
| `--ssoDomain` | The destination domain to sync memberships to. |
| `--csvFilePath` | Path to a CSV file containing a list of user emails to sync. |
| `--matchByUserName` | Match users by their `username` property instead of `email`. |
| `--matchToLocalPart`| Match the local-part of the source user's email to the destination user's `username`. Mutually exclusive with `--ssoDomain`. |

#### `sync` Flow Diagram

![sync-flow-diagram](docs/images/sync-flow-diagram.svg)

### `get-users`: Getting SSO Users

This command retrieves SSO users from the SSO connection tied to the Snyk Group. You can redirect the output to a CSV file.

#### Get All Users

```bash
snyk-sso-membership get-users <groupID> > myusers.csv
```

#### Get Users by Domain, Email, or CSV

```bash
# Get all users by email domain
snyk-sso-membership get-users <groupID> --domain=source.com > myusers.csv

# Get a single user by email
snyk-sso-membership get-users <groupID> --email=user1@source.com > myusers.csv

# Get a list of users from a CSV file
snyk-sso-membership get-users <groupID> --csvFilePath="./users.csv" > myusers.csv
```

> **Note:** `--domain` accepts a single domain or a comma-separated list. Users whose email (or username with `--matchByUserName`) ends with any of the listed domains are included. For example: `--domain=robsworld.com,gmail.com`

### `delete-users`: Deleting SSO Users

This command deletes SSO users by email address or unique user ID.

> [!NOTE]
> The `delete-users` command triggers standard Snyk email notifications to affected users (e.g., "Your Snyk account was deleted"). This is a platform-level behavior and cannot be configured.

#### Delete Users by Domain, Email, or CSV

```bash
# Delete all users by email domain
snyk-sso-membership delete-users <groupID> --domain=source.com

# Delete a single user by email
snyk-sso-membership delete-users <groupID> --email=user1@source.com

# Delete a list of users from a CSV file
snyk-sso-membership delete-users <groupID> --csvFilePath="./users.csv"
```

### `get-users` and `delete-users` Command Options

| Option | Description |
| --- | --- |
| `--matchByUserName` | Use this flag to identify users by their `username` property instead of `email`. |

## IdP Migration Workflow

If you need to migrate users from one Identity Provider (IdP) to another while preserving all their Group and Organization memberships, this tool provides a specialized 3-step workflow using JSON export/import.

**Use Cases:**
- Migrating from one SSO provider to another (e.g., Okta → Azure AD)
- Changing email domains while maintaining all user permissions
- Consolidating users from multiple Snyk Groups into a single new IdP

**📖 Complete Documentation: [IdP Migration Workflow Guide](docs/IDP_MIGRATION_WORKFLOW.md)**

The dedicated guide includes:
- **Step-by-step instructions** for the 3-stage migration process
- **Command reference** for `generate-memberships-json`, `assign-memberships-from-json`, and `delete-memberships-from-json`
- **Multi-group support** for consolidating users from multiple Snyk Groups
- **JSON schema documentation** and examples
- **Troubleshooting tips** and best practices
- **Performance expectations** for large-scale migrations (1000+ users)
- **Rollback strategies** for safe migrations

This workflow allows you to migrate users without deleting their accounts, which is critical when users may temporarily exist on both SSO connections simultaneously.

## How Snyk User Profiles are Matched

A Snyk User is identified on the SSO connection through their profile attributes. The tool uses these attributes to find matching source and destination users.

**Example User Profiles:**
```json
{
    "type": "user",
    "id": "bb5f4804-7190-444e-99dc-47604ccd4867",
    "attributes": {
        "name": "Alpha Bravo Charlie",
        "email": "abc.xyz@xyz.com",
        "username": "abc@abc.com",
        "active": true
    }
},
{
    "type": "user",
    "id": "9fe58235-93c8-47b0-807a-ab3ac0bdb5aa",
    "attributes": {
        "name": "Alpha Bravo Charlie",
        "email": "abc.xyz@def.com",
        "username": "abc.xyz",
        "active": true
    }
}
```

## ⚠️ Important Behavior

> [!WARNING]
> Please read these points carefully before using the tool.
>
> *   **Destructive Sync:** The `sync` command performs a **full synchronization**. The destination user's list of Organization memberships will become an exact mirror of the source user's list. Any memberships the destination user had that the source user did not will be **deleted**.
> *   **Email Notifications:** The `delete-users` command triggers standard Snyk email notifications to the affected users (e.g., "Your Snyk account was deleted"). This is a platform-level behavior and cannot be configured.

## Logging

For every execution, a log file named `snyk-sso-membership_run_<YYYYMMDDHHMMSS>.log` is created in the directory where the tool is run.

## License

This project is licensed under the [Apache 2.0 License](LICENSE).