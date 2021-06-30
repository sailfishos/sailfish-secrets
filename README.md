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

A community-developed plugin exists to provide GnuPG functionality to clients, including:

* `GnuPG OpenPGP Plugin`: provides cryptographic operations using GnuPG
* `GnuPG S/MIME Plugin`: provides signing and verification support for emails
* `GnuPG PinEntry Plugin`: provides integration with GnuPG pin-entry for authentication

Huge thanks for Damien Caliste for his ongoing work on this plugin and the framework more generally.

### Secrets and Crypto Libraries

#### 1. Client libraries

The Sailfish Secrets and Sailfish Crypto C++ (Qt) libraries expose the capability of the
Sailfish OS Secrets and Crypto Framwork to client applications.  They provide Qt-style APIs
with request objects which emit appropriate signals upon operation completion, and which
can be extended in the future without breaking binary or source compatibility. All IPC is hidden
as an implementation detail, as the D-Bus APIs are NOT stable, and no compatibility guarantees
are provided for those.

A QML API has also been implemented, allowing clients to utilize the Sailfish OS Secrets and Crypto
Framework within QML applications, however this API should be considered experimental and
subject to change at this time.

A (glib-based) C API has also been implemented, allowing clients to utilize the Sailfish OS Secrets
and Crypto Framework within non-Qt applications, however this API should be considered experimental
and subject to change at this time.

#### 2. Plugin libraries

Extensibility points that can implement various functionality.

Secrets:

* `StoragePlugin`: non-encrypted storage capabilities
* `EncryptionPlugin`: provides encryption for secrets stored in non-encrypted storage plugins
* `EncryptedStoragePlugin`: implements block-level encryption and storage together (eg. SQLCipher, secure peripherals)
* `AuthenticationPlugin`: provides mechanisms to authenticate the identity of the user when performing operations

Crypto:

* `CryptoPlugin`: provides all kinds of cryptographic capabilities, such as signing, encryption, etc.

A `CryptoPlugin` may also implement the `EncryptedStoragePlugin` interface, in order to provide not
just cryptographic operations (signing, encryption, etc) to clients, but also key generation and
storage capabilities.

## Build requirements:

For Sailfish OS:

1. Standard MerSDK
2. [sqlcipher](https://github.com/sailfishos/sqlcipher.git) package installed into the target

For your Linux desktop:

1. Qt 5.6.3 (downloadable from official Qt SDK, you need this exact version, because sailfish-secrets bundles
qtsqlcipher, which depends on Qt internals that are not compatible between versions)
2. sqlcipher package (installed from your distro's package manager)

If you wish to build the GnuPG plugins, you will need to install libgpg-error, gpgme-devel, and libassuan-devel.

## Building

1. Clone the repo and go inside:

    ```bash
    git clone https://github.com/sailfishos/sailfish-secrets.git sailfish-secrets
    cd sailfish-secrets
    ```
2. Run the usual build command for Sailfish OS projects:

    ```bash
    # inside Sailfish OS SDK prompt:
    mb2 build
    ```

## Running the unit tests:

0. Stop the secrets daemon if it is already running on the system

   ```bash
   systemctl --user stop sailfish-secretsd
   ```

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

5. Run the cryptorequests autotest

   ```bash
   devel-su -p /opt/tests/Sailfish/Crypto/tst_cryptorequests
   ```

6. Run the manual system tests

   ```bash
   devel-su -p /opt/tests/Sailfish/Crypto/matrix/run-matrix-tests.sh
   ```

## Architectural Overview:

The client-facing API is primarily a thin wrapper around P2P DBus calls to
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
  |   Access Control    |<------<|                                |
  |   Daemon (future)   |>------>|                                |
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

  * All DBus flows use P2P DBus (i.e. Unix Domain Sockets)
  * The system access control daemon is not yet implemented
    so currently access control is performed by the secrets
    daemon itself, based on which application created the
    secret (or collection of secrets) in question
```

## Current Status:

The client C++ API is mostly stable, however it is expected that the
implementation of the daemon (and potentially the plugin API) will
change in the future as more use-cases and requirements are made
known to us.

Extensions to the client API are also expected (for example,
message authentication code operations, key exchange operations,
certificate handling support, and supporting passing file descriptors
as operation parameters), however these will be added in a binary
and source compatible manner.

Known open work items:

- Affecting both Secrets and Crypto domains:
  - fine-grained access control (requires access-control daemon, TBA)
  - use request-specific data structures instead of QVariantList
    when marshalling incoming requests from the queue to the handler
  - unit test coverage needs to be expanded
  - on-going code review would be appreciated

- Secrets:
  - improve the lock/unlock semantics (e.g. automatic unlock flows)

- Crypto:
  - review from domain expert would be greatly appreciated
  - implement support for certificates
  - implement support for message authentication codes
  - improve support for key exchange operations

It is expected that fixes will be able to be made without breaking either
binary or source compatibility for client applications, due to the
architecture of the framework and the way the C++ API was implemented.

## Contributions

Community contributions are very welcome, especially:

  - API and code review
  - bug fixes
  - unit test case contributions
  - plugin implementation contributions (e.g. secure-peripheral device plugins)
  - daemon implementation improvements (e.g. request data marshalling structures)

Please get in touch via IRC (#sailfishos@oftc.net) or email if you
are willing to help out :-)

Huge thanks in particular to Damien Caliste who has contributed a variety
of fixes, pointed out several API design flaws, extensively tested the
framework, and implemented (and contributed) a GnuPG-based plugin.


