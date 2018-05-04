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

## Components

### Secrets daemon

We have a system service (daemon) called `sailfishsecretsd` which listens to connections over
peer-to-peer D-Bus and has two responsibilities:

* Store (and retrieve) sensitive data in secure locations
* Perform cryptographic operations on behalf of clients

Rationale:

* The user's secret keys are never actually exposed to the client application, so
the user doesn't have to trust the client to handle sensitive data correctly. In fact, if
you have a plugin that enables the use of a suitable peripheral, the key is never even loaded
into system memory.
* Clients don't have to "know about cryptography" or be certified, because all crypto
operations are done by plugins which are loaded by the daemon.
* The daemon can expose a uniform API while still being able to load various kinds of plugins.
Such plugins could provide for example: support for secure hardware peripherals, custom
encryption algorithms or signing schemes, etc.
* Plugin developers only have to conform to the plugin API and don't have to worry about
the user-facing API or the GUI.

### Plugins for the secrets daemon

There is a set of default plugins that do not require the user to have special hardware
and use standard free / open source solutions like OpenSSL and SQLCipher under the hood.
These plugins ensure that every Sailfish OS user can benefit from the security and cryptography
work that we are doing.

We also provide some example plugins to help the developers of secure peripherals get started
easily and with less hassle.

There are quite a few different kinds of plugins which means that the API allows complete or
partial customization of the daemon's behavior.

The default plugins are:

* `SqlCipherPlugin` which stores encrypted data in SQLCipher and shares code with the
`OpenSslCryptoPlugin` for crypto operations
* `PasswordAgentAuthPlugin` which talks to the Sailfish OS password agent to display
system dialogs for the user

Other, example plugins:

* `OpenSslCryptoPlugin`: provides cryptographic operations using OpenSSL under the hood
* `InAppAuthPlugin`: allows the application itself to perform user authentication instead of
making the system handle it (mostly for testing purposes)
* `SQLitePlugin`: which provides non-encrypted storage ability in SQLite
* `OpenSslPlugin`: which provides encryption ability with OpenSSL for non-encrypted storage plugins
* `ExampleUsbTokenPlugin`: which provides an example for plugin developers who want to add support
for their secure peripherals

### Secrets and crypto libraries

#### 1. Client libraries

These libraries are intended for consumption by client applications. They will take care of the
D-Bus connection for you, so you don't have to worry about it. There is also a QML API, so
you can utilize sailfish-secrets from QML apps.

#### 2. Plugin libraries

Extensibility points that can implement various functionality.

Secrets:

* `StoragePlugin`: non-encrypted storage abilities
* `EncryptionPlugin`: provides encryption abilities that can be used together with non-encrypted storage plugins
* `EncryptedStoragePlugin`: for devices that implement encryption and storage together (eg. secure peripherals)
* `AuthenticationPlugin`: provides ways to authenticate the identity of the user towards the secrets daemon

Crypto:

* `CryptoPlugin`: provides all kinds of cryptographic capabilities, such as signing, encryption, etc.

## Build requirements:

For Sailfish OS:

1. Standard MerSDK
2. [sqlcipher](https://github.com/sailfishos/sqlcipher.git) package installed into the target

For your Linux desktop:

1. Qt 5.6.3 (downloadable from official Qt SDK) - yes you need this exact version, because sailfish-secrets bundles
qtsqlcipher, which depends on Qt internals that are not compatible between versions.
2. sqlcipher package (installed from your distro's package manager)

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

