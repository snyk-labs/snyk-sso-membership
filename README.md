![Snyk logo](https://snyk.io/style/asset/logo/snyk-print.svg)

# snyk-sso-membership

A Go CLI tool executable for synchronizing Snyk Single Sign On (SSO) memberships of a provisioned SSO User from a source SSO domain to a destination SSO domain.

## Users Memberships

A Snyk SSO is bound to a Snyk Group. Snyk SSO users could be provisioned with the same email _name_ identifier across multiple domains associated with the SSO using a *non custom mapping* SSO setup at the Identity Provider. `snyk-sso-membership` identifies such existent duplicated Users and synchronizes the User Group and Org memberships across 2 domains with the same _Role_ and list of _Orgs_.

## Deleting SSO Users on Snyk

Deleting Snyk SSO Users on a specified domain is supported. This is catered for use cases of migration of a SSO domain to a new domain with subsequent removal of Snyk Users on the deprecated domain. These users are identified through their Snyk profile matching the deprecated domain.

## Getting started

To build `snyk-sso-membership`:
```
make build
```

## Prerequisites

- Snyk Service Account API Key token with Group Admin role
- Set API Key token to an exported environment variable `SNYK_TOKEN`

```bash
export SNYK_TOKEN=<api_token>
```

## Usage
### Executing sync Users Membership

Specify Snyk `groupID` as an argument with `domain` and `ssoDomain` flags

#### All Users

This lookups the SSO users to find all Users sharing the same local-part email username for synchronization across domains.

```bash
snyk-sso-membership sync <groupID> --domain=source.com --ssoDomain=destination.com
```

#### Selective Users (through a CSV file)
Example CSV (users.csv)

```
user1@source.com,
user2@source.com,
```

```bash
snyk-sso-membership sync <groupID> --domain=source.com --ssoDomain=destination.com --csvFilePath="./users.csv"
```

#### Matching Source User Option (matchByUserName)
Use `matchByUserName` flag to search a source domain User on the SSO connection with a Snyk profile matching `username` to the requested email. The default value of this optional flag is `false` i.e. search Snyk profile by `email` property.

Example:

For a Snyk User `abc` with a source profile of username as `abc@source.com` and email as `abc@sg.source.com`, `matchByUserName` option will find a User self having a profile of `username` (instead of `email`) as `abc@source.com` and then lookup the destination SSO domain User with a profile of `email` as `abc@destination.com`.

```bash
snyk-sso-membership sync <groupID> --domain=source.com --ssoDomain=destination.com --csvFilePath="./users.csv" --matchByUserName
```

#### Matching Destination User Option (matchToLocalPart)
Use `matchToLocalPart` flag to find the corresponding destination SSO domain User on the SSO connection with a Snyk profile matching `username` to the local-part of the source domain email. This is applicable in a setup of unique User identification in a non-email format string e.g. through SAML NameID

Example:

For a Snyk User `abc` with a source profile of email as `abc@source.com`, `matchToLocalPart` option will find a corresponding User having a profile of `username` (instead of `email`) as strictly `abc`.

```bash
snyk-sso-membership sync <groupID> --domain=source.com --ssoDomain=destination.com --csvFilePath="./users.csv" --matchToLocalPart
```

These commands will synchronize Group and Org memberships of SSO Users on the `source.com` domain to their corresponding self on `destination.com` domain.
The 2 optional flags allow selection of the source domain User (`matchByUserName`) and selection of the destination SSO domain User (`matchToLocalPart`) respectively.

### Deleting SSO Users
Deleting a SSO user is applicable for a single domain and does not lookup a corresponding User on the `destination.com` domain. 

```bash
snyk-sso-membership delete-users <groupID> --domain=source.com
```

```bash
snyk-sso-membership delete-users <groupID> --email=User1@source.com
```

```bash
snyk-sso-membership delete-users <groupID> --csvFilePath="./users.csv"
```

#### Deleting SSO Users Option (matchByUserName)
This optional flag will identify the User by their Snyk profile through its `username` property instead of `email` property.

Example:

```bash
snyk-sso-membership delete-users <groupID> --csvFilePath="./users.csv" --matchByUserName
```

## Logging

A log file named `snyk-sso-membership_run_<YYYYMMDDHHMMSS>.log` is created for a run of the snyk-sso-membership tool.

## Note

- Full synchronization is performed. i.e. in (A -> B) sync, B user list of Org memberships mirror exact of A. Any B's memberships to Orgs without A are deleted.

- Default email notifications of e.g. Snyk detected vulnerabilities based on the subscribed Snyk Group and Org settings will be applied on Snyk SSO Users with synchronization of those memberships completed on the destination domain.

- Deleting a SSO User will trigger an immediate "Your Snyk account was deleted" email to the Snyk SSO user on the specified domain or email addresses.
