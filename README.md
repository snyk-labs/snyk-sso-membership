![Snyk logo](https://snyk.io/style/asset/logo/snyk-print.svg)

# snyk-sso-membership

A Go CLI tool executable for synchronizing Snyk Single Sign On (SSO) memberships of a provisioned SSO User from a source SSO domain to a destination SSO domain.

## Users Memberships

A Snyk SSO is bound to a Snyk Group. Snyk SSO users could be provisioned with the same email _name_ identifier across multiple domains associated with the SSO using a *non custom mapping* SSO setup at the Identity Provider. `snyk-sso-membership` identifies such existent duplicated Users and synchronizes the User Group and Org memberships across 2 domains with the same _Role_ and list of _Orgs_.

## Deleting SSO Users on Snyk

Deleting Snyk SSO Users on a specified domain is supported. This is catered for use cases of migration of a SSO domain to a new domain with subsequent removal of Snyk Users on the deprecated domain. These users are identified through their Snyk `email` property value matching the deprecated domain.

## Getting started

To build `snyk-sso-membership`:
```
make build
```

## Prerequisites

- Snyk Service Account API Key token with Group Admin role 

## Usage
### Executing sync Users Membership

- Specify Snyk `groupID` as an argument with `domain` and `ssoDomain` flags

```bash
snyk-sso-membership sync <groupID> --domain=source.com --ssoDomain=destination.com
```
This will synchronize Group and Org memberships of SSO Users on the `source.com` domain to their corresponding self on `destination.com` domain.

### Deleting SSO Users

```bash
snyk-sso-membership delete-users <groupID> --domain=source.com
```

```bash
snyk-sso-membership delete-users <groupID> --email=User1@source.com
```

```bash
snyk-sso-membership delete-users <groupID> --email=User1@source.com,User2@source.com
```

## Note

- Full synchronization is performed. i.e. in (A -> B) sync, B user list of Org memberships mirror exact of A. Any B's memberships to Orgs without A are deleted.

- Default email notifications of e.g. Snyk detected vulnerabilities based on the subscribed Snyk Group and Org settings will be applied on Snyk SSO Users with synchronization of those memberships completed on the destination domain.

- Deleting a SSO User will trigger an immediate "Your Snyk account was deleted" email to the Snyk SSO user on the specified domain or email addresses.
