# Keycloak Token Exchange SPI Examples

The purpose of the examples in this repo is to demonstrate the use of the upcoming [Token Exchange SPI](https://github.com/keycloak/keycloak-community/pull/213) in Keycloak.

## Setup

### Building and installing
1. Check out and build the [token-exchange-spi](https://github.com/CarrettiPro/keycloak/tree/token-exchange-spi) Keycloak branch;
1. Build the project and deploy the JAR with the examples to Keycloak.

### Importing realm data
Go to Keycloak admin console, then import `alice-realm.json` and `bob-realm.json`.

### Running the examples
Run Keycloak:
```
bin/standalone.sh -Dkeycloak.profile=preview
```

Run Postman, open the `Token Exchange SPI Examples` collection and run it. Alternatively, use Newman:
```
newman run "Token Exchange SPI Examples.postman_collection.json"
```

## Examples

### Cross-realm impersonation
In Keycloak, the [impersonation](https://www.keycloak.org/docs/latest/securing_apps/index.html#impersonation) feature only works withing a realm (i.e. the impersonator and the user to be impersonated must belong to the same realm). Cross-realm token exchange could be [emulated](https://lists.jboss.org/pipermail/keycloak-user/2019-March/017477.html) to some extent using brokering, but this solution has a lot of limitations.

In this example, simple brokerless trust is established between the realms:

* both impersonator's and target user's realms must belong to the same Keycloak instance;
* impersonator's and target user's realms must be different;
* the call must be made to the target realm's token endpoint;
* the impersonator must possess the `x-impersonation-{REALM}` realm role, where `{REALM}` is the name of the target realm;
* the target user must belong to the `X-Impersonation` group.

> :warning: In other words, any RealmA user possessing the `x-impersonation-RealmB` role will be able to impersonate any RealmB user, provided that the latter belongs to the `X-Impersonation` group. This pseudo ACL is obviously too weak for production use, and has been added for demo purposes only.

If all conditions are met, then the following direct exchange becomes possible:

```
curl -X POST \
    -d "client_id=starting-client" \
    -d "client_secret=geheim" \
    --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
    -d "subject_token=...." \
    --data-urlencode "requested_token_type=urn:ietf:params:oauth:token-type:access_token" \
    -d "audience=target-client" \
    -d "scope=foobar" \
    -d "requested_subject=wburke" \
    http://localhost:8080/auth/realms/myrealm/protocol/openid-connect/token
```

The result of the exchange is the following access token:

```json
{
  "exp": 1620249595,
  "iat": 1620249295,
  "jti": "8d7a25c9-9201-4949-9e74-848947e71f35",
  "iss": "http://localhost:8080/auth/realms/myrealm",
  "aud": "target-client",
  "sub": "a2482293-2712-4730-90b9-3027f1370727",
  "typ": "Bearer",
  "azp": "starting-client",
  "session_state": "d9911a93-f8b7-4a3a-973e-f7534f08b61f",
  "acr": "1",
  "realm_access": {
    "roles": [
      "offline_access",
      "uma_authorization"
    ]
  },
  "resource_access": {
    "account": {
      "roles": [
        "manage-account",
        "manage-account-links",
        "view-profile"
      ]
    }
  },
  "scope": "email profile foobar x-impersonation",
  "email_verified": false,
  "act": {
    "iss": "http://localhost:8080/auth/realms/alice",
    "sub": "7705a5cc-099a-452d-9c97-32e47acb8bac",
    "preferred_username": "alice"
  },
  "preferred_username": "wburke"
}
```

Please note the presence of the `x-impersonation` scope automatically added by the token exchange provider, as well as the `act` claim containing impersonator info.