![Snyk logo](https://snyk.io/style/asset/logo/snyk-print.svg)
# **Snyk SSO Membership Tool**

This is a command-line (CLI) tool built in Go to help Snyk Group Administrators manage user memberships during a Single Sign On (SSO) domain migration.

This tool helps solve the challenge of migrating Group and Organization memberships of Snyk users who are represented across two different email domains on a SSO connection. Example: 

- `user@source.com` to `user@destination.com` (by `email` property)
- `user@source.com` to `user` (by `username` property)

## **Key Features**

* **Synchronize Memberships**: Copy a user's Snyk Group and Organization roles from a source domain account to a destination domain account.
* **Delete Users**: Bulk-delete Snyk SSO users from a specific domain, useful for decommissioning a deprecated domain after migration.
* **Flexible User Matching**: Provides advanced options to match Snyk users based on email, username property values, or the local-part of an email, accommodating complex identity provider (IdP) setups.

## Snyk User Profiles

A Snyk User is identified on the SSO connection through a Snyk profile e.g.

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

## **⚠️ Important Behavior**

Please read these points carefully before using the tool.

* **Destructive Sync:** The `sync` command performs a **full synchronization**. The destination-domain user's list of Organization memberships will become an exact mirror of the source user's list. Any memberships the destination-domain user had that the source-domain user did not will be **deleted**.
* **Email Notifications:** The `delete-users` command will trigger standard Snyk email notifications to the affected users. For example, a deleted user will immediately receive an email stating "Your Snyk account was deleted". This email notification is handled by Snyk platform and is not configurable.

## **Getting Started**

### **Prerequisites**

You will need a Snyk Service Account API token with:

- **Group Admin** role
- Exported as an environment variable named `SNYK_TOKEN`

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

You can provide a CSV file containing a list of source-domain user emails to sync.

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

* `--matchByUserName` (Optional Flag): By default, the tool matches the source-domain user by their Snyk user `email` property value. Use this flag if the user's identifying email (e.g. `user@source.com`) is in their `username` profile property instead.
* `--matchToLocalPart` (Optional Flag): Use this for advanced cases where a destination-domain user is identified by a non-email address username (e.g. SCIM provisioned users based on IdP `nameIdAttributes`). This option will match _local-part_ (the part before the `@`) of the source-domain user's email address against the `username` property value of a destination-domain user on the SSO connection. By default without this flag, the identification of a destination-domain user is applied by matching a "_local-part@ssoDomain_" value against the `email` property value. This flag is therefore mutually exclusive to the `ssoDomain` flag.

#### **`sync` Flow Diagram**

![sync-flow-diagram](docs/images/sync-flow-diagram.svg)

These 2 command options provide flexibility on identifying and matching a source-domain to its similar destination-domain Snyk user. If these CLI flags are not provided, they are defaulted to false.

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
