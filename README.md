# Sailfish Secrets

A storage and crypto API for using in Sailfish OS.

## Brief Description:

The Secrets API allows clients to securely store data via a system
daemon which delegates operations to plugins which are loaded into the
system daemon process.  Those plugins may optionally use a Secure
Peripheral or Trusted Execution Environment application as their actual
backend.
    
The Crypto API allows clients to perform cryptographic operations via
the same system daemon which delegates operations to crypto plugins
which are loaded into the system daemon process.  Those plugins may
optionally use a Secure Peripheral or Trusted Execution Environment
application as their actual backend, and if the plugin also supports
securely storing Secrets, the cryptographic operations may be performed
without ever compromising the security of the secret keys (i.e., they
are not returned to the client process address space, and in the case
of Secure Peripheral or TEE application backends, they are not returned
to the system daemon process address space after initial storage).

## Building requirements:

1. Standard MerSDK
2. [sqlcipher](https://github.com/sailfishos/sqlcipher.git) package installed into the target

## Building

1. Clone the repo and go inside:

    ```bash
    git clone https://github.com/sailfishos/sailfish-secrets.git sailfish-secrets
    cd sailfish-secrets
    ```
2. Run the build command for usual sailfish os git-projects:

    ```bash
    mb2 build
    ```

## Running:

1. Run the secrets daemon in autotest mode with debugging enabled

    ```bash
    QT_LOGGING_RULES="*.debug=true" devel-su -p /usr/bin/sailfishsecretsd --test
    ```

2. Run the secrets autotest

    ```bash
    devel-su -p /opt/tests/Sailfish/Secrets/tst_secrets
    ```

3. Run the crypto autotest

    ```bash
    devel-su -p /opt/tests/Sailfish/Crypto/tst_crypto
    ```

4. Run the cryptosecrets autotest

    ```bash
    devel-su -p /opt/tests/Sailfish/Crypto/tst_cryptosecrets
    ```

## Architectural Overview:

The client-facing API is primarily a thin wrapper around DBus calls to
the system daemon (sailfishsecretsd).  That daemon manages a queue of
incoming client requests for each separate domain (Secrets + Crypto),
and handles the requests by performing some book-keeping (and, in the
future, fine-grained access control) before delegating the request to
the appropriate backend plugin.

In some cases, user interaction will be required to complete a request,
and in those cases the daemon will manage a user interaction flow to
retrieve the appropriate confirmation / lock code / secret key.
The actual user interface shown to the user will either be provided
by the Sailfish OS system (e.g., System User Interaction flow, where
the secrets daemon will request the Lock Screen UI daemon to show the
appropriate UI), or, in some special cases (e.g., application-specific
data requests) the client application can provide the UI via a plugin.

```
                                      +-------------+
                                      |    Secure   |
                                      |  Peripheral |
                                      +-------------+
                                          ^    ^
                                          |    |
                                    r-----'    '------,
                                    |                 |
                                 +--^---+-------+ +---^---+-------+
                                 |crypto|plugins| |secrets|plugins|
  +---------------------+        +------+-------+-+-------+-------+
  |    Access Control   |<------<|                                |
  |       Daemon        |>------>|                                |
  +---------------------+  DBus  |                                |
                                 |        sailfishsecretsd        |
  +---------------------+        |                                |
  |     Lock Screen     |<------<|                                |
  |       Daemon        |>------>|                                |
  | (SystemInteraction) |  DBus  |                                |
  +---------------------+        +--------------------------------+
                                     V ^            ^   ^
                                     | |            |   |
         r---------------------------' |            |   |
         | .---------------------------'            |   |
         | |               DBus                     |   |
         V ^                                        |   |
  +--------------------------+                      |   |
  |     Sailfish Secrets     |                      |   |
  |        UI Plugin         |                      |   |
  | (ApplicationInteraction) |                      |   |
  +--------------------------+  (Crypto API Call)   |   |
  |                          |        DBus          |   |
  |                          |>---------------------'   |
  |         Client           |                          |
  |        Application       |  (Secrets API Call)      |
  |                          |        DBus              |
  |                          |>-------------------------'
  +--------------------------+
```

## Current Status:

This code is Work-In-Progress.  The API will change significantly!
Known open work items:

- Affecting both:
  - access control (requires access-control daemon, TBA)
  - should we use system DBus instead of peer-to-peer DBus?
  - use request-specific data structures instead of QVariantList
    when marshalling incoming requests from the queue to the handler
  - full API and code review is required
  - unit test coverage needs to be greatly expanded

- Secrets:
  - improve the lock/unlock semantics?

- Crypto:
  - certificates implementation currently missing, API is sketch only
  - add CSPRNG and Hash API and daemon plumbing
  - polish the API:
      - possibly separate key-length (bits) from algorithm
      - is digest parameter necessary for encrypt/decrypt ops
      - do we need stream-cipher-session API support/continueEncrypt?
      - ... no doubt there are many other things requiring polish
  - plugin implementations:
      - finish implementing the opensslcryptoplugin
      - potentially add other plugins (TEE/SecurePeripheral etc)
  - in general, the entire Crypto domain needs a domain expert to
    review carefully, point out architectural issues, and offer
    advice about implementation details.

## Contributions

Community contributions are very welcome, especially:

  - API and code review
  - bug fixes
  - plugin implementation contributions (e.g. SQLCipher-based plugin)
  - unit test case contributions

Please get in touch via IRC (#jollamobile@freenode) or email if you
are willing to help out :-)

