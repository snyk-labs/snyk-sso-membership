![Snyk logo](https://snyk.io/style/asset/logo/snyk-print.svg)
# **Snyk SSO Membership Tool**

A command-line (CLI) tool built in Go to help Snyk Group Administrators manage user memberships during a Single Sign On (SSO) domain migration.

This tool helps solve the challenge of migrating users who have the same username but will exist across two different email domains (e.g.,

`user@source.com` and `user@destination.com`).

## **Key Features**

* **Synchronize Memberships**: Copy a user's Snyk Group and Organization roles from a source domain account to a destination domain account.
* **Delete Users**: Bulk-delete Snyk SSO users from a specific domain, useful for decommissioning a deprecated domain after migration.
* **Flexible User Matching**: Provides advanced options to match users based on email, username, or the local-part of an email, accommodating complex identity provider (IdP) setups.

## **⚠️ Important Behavior**

Please read these points carefully before using the tool.

* **Destructive Sync:** The `sync` command performs a **full synchronization**. The destination user's list of Organization memberships will become an exact mirror of the source user's list. Any memberships the destination user had that the source user did not will be **deleted**.
* **Email Notifications:** Both the `sync` and `delete-users` commands will trigger standard Snyk email notifications to the affected users. For example, a deleted user will immediately receive an email stating "Your Snyk account was deleted".

## **Getting Started**

### **Prerequisites**

You will need a Snyk Service Account token with the

**Group Admin** role.

This token must be set as an environment variable named

`SNYK_TOKEN`.

```bash
export SNYK_TOKEN=<your_snyk_api_token>
```

### **Build**

To build the

`snyk-sso-membership` executable:

```bash
make build
```

## **Usage**

The tool has two main commands: `sync` and `delete-users`.

### **`sync`: Synchronizing User Memberships**

This command synchronizes Group and Organization memberships from users on a source domain to users on a destination domain.

#### **Sync All Users in a Group**

This looks up all SSO users in a Group and finds pairs of users across the two domains who share the same local-part (username) in their email address.

```bash
snyk-sso-membership sync <groupID> --domain=source.com --ssoDomain=destination.com
```

#### **Sync a Selective List of Users**

You can provide a CSV file containing a list of source user emails to sync.

Example

`users.csv` file:

Code snippet

```
user1@source.com,
user2@source.com,
```

Command:

```bash
snyk-sso-membership sync <groupID> --domain=source.com --ssoDomain=destination.com --csvFilePath="./users.csv"
```

#### **`sync` Command Options**

* `--matchByUserName` (Optional Flag): By default, the tool matches the source user by their Snyk user profile
   `email`. Use this flag if the user's identifying email (e.g. `user@source.com`) is in their `username` profile property instead.
* `--matchToLocalPart` (Optional Flag): Use this for advanced cases where the destination user is identified by a non-email username (e.g., from a SAML NameID). This will match the
   `username` of the destination user to the local-part (the part before the `@`) of the source user's email. This flag is therefore mutually exclusive to the `ssoDomain` flag.

### **`delete-users`: Deleting SSO Users**

This command deletes SSO users by email addresses or the unique identifier of a User.

#### **Delete All Users in a Domain**

```bash
snyk-sso-membership delete-users <groupID> --domain=source.com
```

#### **Delete Users by Email or CSV**

```bash
# Delete a single user by email
snyk-sso-membership delete-users <groupID> --email=user1@source.com

# Delete a list of users from a CSV file
snyk-sso-membership delete-users <groupID> --csvFilePath="./users.csv"
```

#### **`delete-users` Command Options**

* `--matchByUserName` (Optional Flag): Use this flag to identify and delete users by their Snyk user profile
   `username` property instead of their `email` property.

## **Logging**

For every execution, a log file named

`snyk-sso-membership_run_<YYYYMMDDHHMMSS>.log` is created in the directory where the tool is run.
