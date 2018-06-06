/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "extensionplugins.h"

#include <QObject>
#include <QString>
#include <QSharedData>

SAILFISH_SECRETS_API Q_LOGGING_CATEGORY(lcSailfishSecretsPlugin, "org.sailfishos.secrets.daemon.plugin", QtWarningMsg)

using namespace Sailfish::Secrets;

/*!
  \class PluginBase
  \brief Provides the base interface for extension plugins for the Sailfish OS Secrets and Crypto Framework.

  PluginBase is an abstract base class which provides an interface which all extension plugins
  must implement.  This interface includes some information about the plugin (including its
  name and version, and whether or not it supports locking), as well as locking operation methods.

  Extension plugins are loaded by the Sailfish OS Secrets and Crypto Framework daemon, and
  the functionality of those plugins is exposed to clients via the Secrets and Crypto API.

  There are a variety of extension plugin types which each extend PluginBase,
  which define specific interfaces which concrete derived types must implement.
  A list of the available Secrets extension plugin types follows:

  \list
  \li \l{Sailfish::Secrets::AuthenticationPlugin} perform suser authentication and verification
  \li \l{Sailfish::Secrets::EncryptionPlugin} encrypts secret data for secrets stored in a \l{Sailfish::Secrets::StoragePlugin}
  \li \l{Sailfish::Secrets::StoragePlugin} provides unencrypted storage for secrets
  \li \l{Sailfish::Secrets::EncryptedStoragePlugin} provides encrypted storage for secrets
  \endlist

  In addition, there also exists the \l{Sailfish::Crypto::CryptoPlugin} extension plugin type,
  which provides cryptographic functionality to clients.  If a particular plugin implements
  both the \l{Sailfish::Crypto::CryptoPlugin} and \l{Sailfish::Secrets::EncryptedStoragePlugin}
  interfaces then it is able to secure store cryptographic keys as well as perform cryptographic
  operations using those keys, and is referred to as a Crypto-Storage Plugin.

  Plugin implementers should not extend PluginBase directly, but should instead derive from
  one of the above-listed plugin types (or both CryptoPlugin and EncryptedStoragePlugin if
  they are implementing a Crypto-Storage plugin).

  Plugin implementers must be aware that the information reporting methods (name(), version(),
  supportsLocking(), and supportsSetLockCode()) will be invoked from the main thread of the
  secrets daemon, while the various locking operation methods (isLocked(), lock(), unlock(),
  and setLockCode()) and availability reporting method (isAvailable()) will be invoked from a
  separate thread.  Plugins are loaded and plugin instances are constructed in the main thread.

  In order to implement a Secrets extension plugin, plugin implementers should
  specify the following in their .pro file:
  \code
  CONFIG += link_pkgconfig
  PKGCONFIG += sailfishsecretspluginapi
  \endcode

  An example (skeleton) Encrypted Storage plugin (which also implements the
  \c{CryptoPlugin} interface) may be found at:
  https://github.com/sailfishos/sailfish-secrets/tree/master/examples/plugins/examplecryptostorageplugin/
 */

/*!
 * \fn PluginBase::displayName() const
 * \brief Return the translated display name of the plugin
 *
 * This name will be shown to the user of the device in system prompts when
 * an attempt is made to access a secret or key stored within the plugin.
 * It should be a human-readable string, which is informative for the user,
 * and may need to be translated into different languages if the display
 * name is not a proper noun.
 *
 * For example, the example encrypted storage plugin based on SQLCipher
 * has the display name "SQLCipher".
 */

/*!
 * \fn PluginBase::name() const
 * \brief Return the name of the plugin
 *
 * This name must be globally unique, so a fully-qualified-domain-name
 * prefix is recommended.
 *
 * For example, the example encrypted storage plugin based on SQLCipher
 * has the name: "org.sailfishos.secrets.encryptedstorage.sqlcipher".
 */

/*!
 * \fn PluginBase::version() const
 * \brief Return the version of the plugin
 *
 * Plugin implementers must document to clients the semantics of every
 * operation they offer through the Sailfish::Secrets or Sailfish::Crypto
 * APIs.  Given that the semantics of the implementation may change from
 * version to version, the version of the plugin must be reported
 * programmatically.
 */

/*!
 * \brief Constructs a new PluginBase instance
 */
PluginBase::PluginBase()
{
}

/*!
 * \brief Cleans up the memory associated with the PluginBase instance
 */
PluginBase::~PluginBase()
{
}

/*!
 * \brief Initialize the plugin
 *
 * Derived types should override this method in order to perform
 * initialization rather than doing so in the constructor, as this
 * method will be called once the loaded plugin is accepted for
 * use by the daemon.
 *
 * This allows the creation of e.g. socket files or other such
 * system side effects to be meaningful and non-interfering.
 */
void PluginBase::initialize()
{
}

/*!
 * \brief Returns true if the plugin supports locking semantics.
 *
 * The default implementation returns false.  This method should
 * be overridden by a specific plugin implementation if it requires
 * an unlock code to be provided by the user prior to use.
 */
bool PluginBase::supportsLocking() const
{
    return false;
}

/*!
 * \brief Returns true if the plugin supports allowing clients to set the lock code.
 *
 * The default implementation returns the same value as supportsLocking(),
 * as most plugins which support locking should allow clients to change
 * the lock code, however this may be overridden by the plugin implementation
 * if the lock code is pre-set and cannot be changed, or if the lock code
 * may only be set initially but thereafter cannot be changed.
 */
bool PluginBase::supportsSetLockCode() const
{
    return supportsLocking();
}

/*!
 * \brief Returns true if the plugin is available for use.
 *
 * The default implementation returns true, as by default it is
 * assumed that the plugin does not require any external hardware
 * to be connected to the device in order to offer functionality
 * to clients.  This method should be overridden by a specific plugin
 * implementation if it requires physical hardware (e.g. a USB token)
 * or network connectivity (e.g. to talk to remote web service) and
 * thus may situationally be either available or unavailable.
 */
bool PluginBase::isAvailable() const
{
    return true;
}

/*!
 * \brief Returns true if the plugin is currently locked.
 *
 * The default implementation returns false, as by default it is
 * assumed that the plugin does not support locking.  This method
 * should be overridden by a specific plugin implementation if it
 * requires an unlock code to be provided by the user prior to use,
 * to ensure that this method reports the lock state of the plugin.
 */
bool PluginBase::isLocked() const
{
    return false;
}

/*!
 * \brief Returns true if the plugin was able to be locked.
 *
 * The default implementation does nothing and returns false, as
 * by default it is assumed that the plugin does not support locking.
 * This method should be overridden in order to perform the locking
 * operation as required, if the plugin requires an unlock code to
 * be provided by the user prior to use.
 */
bool PluginBase::lock()
{
    return false;
}

/*!
 * \brief Returns true if the plugin was able to be unlocked with the provided \a code.
 *
 * The default implementation does nothing and returns false, as
 * by default it is assumed that the plugin does not support locking.
 * This method should be overridden in order to perform the unlocking
 * operation as required, if the plugin requires an unlock code to
 * be provided by the user prior to use.
 */
bool PluginBase::unlock(const QByteArray &code)
{
    Q_UNUSED(code)
    return false;
}

/*!
 * \brief Returns true if the lock code for the plugin was able to be set.
 *
 * The default implementation does nothing and returns false, as
 * by default it is assumed that the plugin does not support locking.
 * If the plugin implementation supports locking, and allows the lock
 * code for the plugin to be changed, then this method should be overridden
 * in order to perform the operation to set the lock code to the given
 * \a newLockCode if the given \a oldLockCode was correct.
 */
bool PluginBase::setLockCode(const QByteArray &oldLockCode,
                             const QByteArray &newLockCode)
{
    Q_UNUSED(oldLockCode)
    Q_UNUSED(newLockCode)
    return false;
}

/*!
  \class EncryptionPlugin
  \brief Specifies an interface to derive an encryption key from
         input data, and encrypt or decrypt secret data.

  The EncryptionPlugin type specifies a simple interface which includes key
  derivation, encryption and decryption operations.

  The functionality provided by a concrete instance of this plugin is not
  intended to be used directly by application clients, but instead is used to
  encrypt (and decrypt) secret data which is stored in unencrypted storage
  (that is, within a StoragePlugin).

  Plugin implementers must be aware that the information reporting methods
  (encryptionType(), and encryptionAlgorithm()) will be invoked from the main
  thread of the secrets daemon, while the various interface operation methods
  (deriveKeyFromCode(), encryptSecret(), and decryptSecret()) will be invoked
  from a separate thread.  Plugins are loaded and plugin instances are
  constructed in the main thread.
 */

/*!
 * \brief Constructs a new EncryptionPlugin instance
 */
EncryptionPlugin::EncryptionPlugin()
    : PluginBase()
{
}

/*!
 * \brief Cleans up any memory associated with the EncryptionPlugin instance
 */
EncryptionPlugin::~EncryptionPlugin()
{
}

/*!
 * \enum EncryptionPlugin::EncryptionType
 *
 * This enum defines the types of encryption capability which may be offered by plugins
 *
 * \value NoEncryption No encryption is performed
 * \value SoftwareEncryption Encryption is performed by "normal" rich execution environment application
 * \value TrustedExecutionSoftwareEncryption Encryption is performed by trusted execution environment (TEE) application
 * \value SecurePeripheralEncryption Encryption is performed by a secure element (SE) hardware peripheral via TEE application
 */

/*!
 * \enum EncryptionPlugin::EncryptionAlgorithm
 *
 * This enum defines the encryption algorithms which may be used by plugins
 *
 * \value NoAlgorithm No encryption is performed
 * \value CustomAlgorithm Some custom encryption algorithm is used by the plugin
 * \value AES_256_CBC The plugin uses AES with 256-bit key in CBC mode to encrypt secrets
 */

/*!
 * \fn EncryptionPlugin::encryptionType() const
 * \brief Returns the type of encryption capability offered by the plugin
 */

/*!
 * \fn EncryptionPlugin::encryptionAlgorithm() const
 * \brief Returns the encryption algorithm which is used by the plugin
 */

/*!
 * \fn EncryptionPlugin::deriveKeyFromCode(const QByteArray &authenticationCode, const QByteArray &salt, QByteArray *key)
 * \brief Derive an encryption key valid for use in encryption and decryption
 *        operations offered by this plugin from the given \a authenticationCode
 *        and \a salt, and write it to the out-parameter \a key.
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::SecretsPluginIsLockedError.
 */

/*!
 * \fn EncryptionPlugin::encryptSecret(const QByteArray &plaintext, const QByteArray &key, QByteArray *encrypted)
 * \brief Encrypt the given \a plaintext with the given \a key and write
 *        the resulting ciphertext to the out-parameter \a encrypted.
 *
 * The \a key is guaranteed to have been derived by this plugin, via a previous
 * call to \a deriveKeyFromCode().
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::SecretsPluginIsLockedError.
 */

/*!
 * \fn EncryptionPlugin::decryptSecret(const QByteArray &encrypted, const QByteArray &key, QByteArray *plaintext)
 * \brief Decrypt the given \a encrypted data with the given \a key and write
 *        the decrypted data to the out-parameter \a plaintext.
 *
 * The \a key is guaranteed to have been derived by this plugin, via a previous
 * call to \a deriveKeyFromCode(), and the \a encrypted data is guaranteed to
 * have been generated by this plugin via a call to \a encryptSecret().
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::SecretsPluginIsLockedError.
 */

/*!
  \class StoragePlugin
  \brief Specifies an interface allowing storage and retrieval of secrets

  The StoragePlugin type specifies an interface which includes a variety
  of operations on secrets and collections of secrets.

  A plugin implementation should derive from this type only if the backing
  store (e.g. USB token, online service, etc) does not support encryption;
  otherwise, the EncryptedStoragePlugin interface should be used.
 */

/*!
 * \enum StoragePlugin::StorageType
 *
 * This enum defines the types of storage capability which may be offered by plugins
 *
 * \value NoStorage No storage is provided
 * \value InMemoryStorage Secrets are stored in-memory only; data won't survive reboot
 * \value FileSystemStorage Normal filesystem storage, e.g. in a database
 * \value SecureFilesystemStorage Storage available to trusted execution environment applications only
 * \value SecurePeripheralStorage Data is stored to a secure hardware peripheral via TEE application
 */

/*!
 * \enum StoragePlugin::FilterOperator
 *
 * This enum defines the possible operators which may be specified for filter operations
 *
 * \value OperatorOr A secret matches the filter if its filter data contains any of the key-value pairs specified in the filter
 * \value OperatorAnd A secret matches the filter if its filter data contains all of the key-value pairs specified in the filter
 */

/*!
 * \brief Constructs a new StoragePlugin instance
 */
StoragePlugin::StoragePlugin()
    : PluginBase()
{
}

/*!
 * \brief Cleans up any memory used by the StoragePlugin instance
 */
StoragePlugin::~StoragePlugin()
{
}

/*!
 * \fn StoragePlugin::storageType() const
 * \brief Returns the type of storage which is exposed by the plugin
 */

/*!
 * \fn StoragePlugin::collectionNames(QStringList *names)
 * \brief Writes the names of collections managed by the plugin to \a names
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::SecretsPluginIsLockedError.
 *
 * If the storage plugin supports storing collections of secrets,
 * it must implement this method by returning the names of currently
 * stored collections into the out-parameter \a names and returning
 * a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Succeeded.
 *
 * Otherwise, it should write an empty list of collection names to the
 * out-parameter \a names and return a Sailfish::Secrets::Result with
 * the result code set to Sailfish::Secrets::Result::Succeeded.
 *
 * If the operation failed due to storage backend failure, the plugin should
 * return a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Failed and the error code set to
 * Sailfish::Secrets::Result::DatabaseError.
 */

/*!
 * \fn StoragePlugin::createCollection(const QString &collectionName)
 * \brief Creates a collection within which to store secrets called \a collectionName
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::SecretsPluginIsLockedError.
 *
 * If the storage plugin supports storing collections of secrets,
 * it must implement this method such that the new collection is created,
 * its name is subsequently returned from \l collectionNames(), and
 * secrets can be stored in it, and the plugin should return a
 * Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Succeeded.
 *
 * If the operation failed due to storage backend failure, the plugin should
 * return a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Failed and the error code set to
 * Sailfish::Secrets::Result::DatabaseError.
 *
 * If a collection with that name already exists in the storage managed
 * by the plugin, the plugin should return a Sailfish::Secrets::Result
 * with the result code set to Sailfish::Secrets::Result::Failed and the
 * error code set to Sailfish::Secrets::Result::CollectionAlreadyExistsError.
 *
 * If the storage plugin does not support the creation of new collections,
 * it should return a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::OperationNotSupportedError.
 */

/*!
 * \fn StoragePlugin::removeCollection(const QString &collectionName)
 * \brief Removes the collection with the given \a collectionName from the
 *        storage managed by the plugin.
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::SecretsPluginIsLockedError.
 *
 * If the storage plugin supports removing collections of secrets,
 * it must implement this method such that the specified collection is removed,
 * its name is subsequently no longer returned from \l collectionNames(), and
 * and the plugin should return a Sailfish::Secrets::Result with the result
 * code set to Sailfish::Secrets::Result::Succeeded.  Any secrets which were
 * stored into this collection should be removed as part of this operation.
 *
 * If the operation failed due to storage backend failure, the plugin should
 * return a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Failed and the error code set to
 * Sailfish::Secrets::Result::DatabaseError.
 *
 * If no collection with that name exists in the storage managed by the plugin,
 * the plugin should return a Sailfish::Secrets::Result
 * with the result code set to Sailfish::Secrets::Result::Failed and the
 * error code set to Sailfish::Secrets::Result::InvalidCollectionError.
 *
 * If the storage plugin does not support the removal of collections,
 * it should return a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::OperationNotSupportedError.
 */

/*!
 * \fn StoragePlugin::setSecret(const QString &collectionName, const QString &secretName, const QByteArray &secret, const Sailfish::Secrets::Secret::FilterData &filterData)
 * \brief Store the given \a secret data identified by the given \a secretName
 *        with the specified \a filterData into the collection identified by
 *        the given \a collectionName.
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::SecretsPluginIsLockedError.
 *
 * If the given \a collectionName is either empty or contains the special
 * value "standalone", this specifies that the secret should not be stored
 * in a collection, but instead should be stored on its own (and thus not
 * be deleted when any particular collection is deleted), if the storage
 * plugin supports storing standalone secrets (and otherwise should return
 * a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::OperationNotSupportedError).
 *
 * If no collection with the given \a collectionName exists in the storage
 * managed by the plugin, the plugin should return a Sailfish::Secrets::Result
 * with the result code set to Sailfish::Secrets::Result::Failed and the
 * error code set to Sailfish::Secrets::Result::InvalidCollectionError.
 *
 * If a secret with the specified \a secretName is already stored
 * in the collection identified by the given \a collectionName, the plugin
 * should return a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::SecretAlreadyExistsError.
 *
 * If the operation failed due to storage backend failure, the plugin should
 * return a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Failed and the error code set to
 * Sailfish::Secrets::Result::DatabaseError.
 */

/*!
 * \fn StoragePlugin::getSecret(const QString &collectionName, const QString &secretName, QByteArray *secret, Sailfish::Secrets::Secret::FilterData *filterData)
 * \brief Write the secret data and filter data associated with the secret
 *        identified by the given \a secretName in the collection identified
 *        by the given \a collectionName into the \a secret and \a filterData
 *        out-parameters respectively.
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::SecretsPluginIsLockedError.
 *
 * If no collection with the given \a collectionName exists in the storage
 * managed by the plugin, the plugin should return a Sailfish::Secrets::Result
 * with the result code set to Sailfish::Secrets::Result::Failed and the
 * error code set to Sailfish::Secrets::Result::InvalidCollectionError.
 *
 * If no secret with the given \a secretName exists in that collection
 * managed by the plugin, the plugin should return a Sailfish::Secrets::Result
 * with the result code set to Sailfish::Secrets::Result::Failed and the
 * error code set to Sailfish::Secrets::Result::InvalidSecretError.
 *
 * If the secret data was retrieved successfully, the plugin should return a
 * Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Succeeded.
 *
 * If the operation failed due to storage backend failure, the plugin should
 * return a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Failed and the error code set to
 * Sailfish::Secrets::Result::DatabaseError.
 */

/*!
 * \fn StoragePlugin::secretNames(const QString &collectionName, QStringList *secretNames)
 * \brief Write the names of secrets which are stored by the plugin in the
 *        collection with the given \a collectionName to the \a secretNames
 *        out-parameter.
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::SecretsPluginIsLockedError.
 *
 * If the given \a collectionName is empty, or is the special value
 * "standalone", the plugin should return the names of standalone secrets
 * which are stored in the storage managed by the storage plugin.  If
 * the plugin does not support storing standalone secrets, it should
 * set the \a secretNames out-parameter to an empty list, and return a
 * Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Succeeded.
 *
 * If no collection with the given \a collectionName exists in the storage
 * managed by the plugin, the plugin should return a Sailfish::Secrets::Result
 * with the result code set to Sailfish::Secrets::Result::Failed and the
 * error code set to Sailfish::Secrets::Result::InvalidCollectionError.
 *
 * If the secret names were retrieved successfully, the plugin should return a
 * Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Succeeded.
 *
 * If the operation failed due to storage backend failure, the plugin should
 * return a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Failed and the error code set to
 * Sailfish::Secrets::Result::DatabaseError.
 */

/*!
 * \fn StoragePlugin::findSecrets(const QString &collectionName, const Sailfish::Secrets::Secret::FilterData &filter, Sailfish::Secrets::StoragePlugin::FilterOperator filterOperator, QStringList *secretNames)
 * \brief Writes the name of each secret in the collection with the specified
 *        \a collectionName into the out-parameter \a secretNames if that
 *        secret has filter data matching the given \a filter according to
 *        the specified \a filterOperator.
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::SecretsPluginIsLockedError.
 *
 * If the given \a collectionName is empty, or is the special value
 * "standalone", the plugin should return the names of standalone secrets
 * which match the filter requirements which are stored in the storage
 * managed by the storage plugin.  If the plugin does not support storing
 * standalone secrets, it should set the \a secretNames out-parameter to an
 * empty list, and return a Sailfish::Secrets::Result with the result code set
 * to Sailfish::Secrets::Result::Succeeded.
 *
 * If no collection with the given \a collectionName exists in the storage
 * managed by the plugin, the plugin should return a Sailfish::Secrets::Result
 * with the result code set to Sailfish::Secrets::Result::Failed and the
 * error code set to Sailfish::Secrets::Result::InvalidCollectionError.
 *
 * If the given \a filterOperator is \c OperatorOr then a secret is deemed
 * to match if its filter data contains any of the key-value pairs specified
 * in the \a filter.  Otherwise, if the \a filterOperator is \c OperatorAnd
 * then a secret is deemed to match only if its filter data contains all of
 * the key-value pairs specified in the \a filter.
 *
 * If the secret names were retrieved successfully, the plugin should return a
 * Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Succeeded.
 *
 * If the operation failed due to storage backend failure, the plugin should
 * return a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Failed and the error code set to
 * Sailfish::Secrets::Result::DatabaseError.
 */

/*!
 * \fn StoragePlugin::removeSecret(const QString &collectionName, const QString &secretName)
 * \brief Remove the secret identified by the given \a secretName within the
 *        collection identified by the given \a collectionName from the storage
 *        managed by the storage plugin.
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::SecretsPluginIsLockedError.
 *
 * If no collection with the given \a collectionName exists in the storage
 * managed by the plugin, the plugin should return a Sailfish::Secrets::Result
 * with the result code set to Sailfish::Secrets::Result::Failed and the
 * error code set to Sailfish::Secrets::Result::InvalidCollectionError.
 *
 * If no secret with the given \a secretName exists in that collection
 * managed by the plugin, the plugin should return a Sailfish::Secrets::Result
 * with the result code set to Sailfish::Secrets::Result::Failed and the
 * error code set to Sailfish::Secrets::Result::InvalidSecretError.
 *
 * If the secret data and any associated filter data was removed successfully,
 * the plugin should return a Sailfish::Secrets::Result with the result code
 * set to Sailfish::Secrets::Result::Succeeded.
 *
 * If the operation failed due to storage backend failure, the plugin should
 * return a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Failed and the error code set to
 * Sailfish::Secrets::Result::DatabaseError.
 */

/*!
 * \fn StoragePlugin::reencrypt(const QString &collectionName, const QString &secretName, const QByteArray &oldkey, const QByteArray &newkey, Sailfish::Secrets::EncryptionPlugin *plugin)
 * \brief Transactionally re-encrypt secret data stored by the storage plugin
 *        using the specified \a oldkey to decrypt the current data, and then
 *        encrypting that data with the \a newkey, by calling the appropriate
 *        methods of the specified EncryptionPlugin \a plugin.
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::SecretsPluginIsLockedError.
 *
 * If the given \a collectionName is empty, or is the special value
 * "standalone", the plugin should re-encrypt the standalone secret
 * identified by the given \a secretName.  Otherwise, the plugin should
 * re-encrypt every secret within the collection identified by the given
 * \a collectionName.
 *
 * Only the secret data (and not the filter data) should be re-encrypted.
 *
 * This method will be invoked if the user changes the master encryption key,
 * if any collection stored within this storage plugin uses master-lock
 * (or device-lock) semantics.  It will also be invoked if the user changes
 * a custom-lock associated with a collection or standalone secret.
 *
 * If the secret data was re-encrypted and updated within storage successfully,
 * the plugin should return a Sailfish::Secrets::Result with the result code
 * set to Sailfish::Secrets::Result::Succeeded.
 *
 * If the operation failed due to storage backend failure, the plugin should
 * return a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Failed and the error code set to
 * Sailfish::Secrets::Result::DatabaseError.
 */

/*!
  \class EncryptedStoragePlugin
  \brief Specifies an interface allowing storage and retrieval of secrets
         into and from an encrypted backing store.

  The EncryptedStoragePlugin type specifies an interface which includes a
  variety of operations on secrets and collections of secrets, where the
  underlying storage is encrypted (e.g. block-level file encryption using
  SQLCipher, or an encrypted USB device).

  The basic mode of operation of this type of plugin is that either the
  entire storage will need to be unlocked (via the \l PluginBase::unlock()
  method) or a specific collection will need to be unlocked (via the
  \l setEncryptionKey() method) before data can be read from or written
  to the storage.  See the included SQLCipher-based plugin for an example
  of a plugin which supports per-collection locking (via setEncryptionKey()).

  If a plugin implements both the EncryptedStoragePlugin interface and the
  Sailfish::Crypto::CryptoPlugin interface, it is referred to as a
  crypto-storage plugin (and can store or provides cryptographic keys for
  use by clients).  See the included example USB token plugin for an example
  of a plugin which provides built-in encryption keys and requires storage
  unlocking, and implements both the EncryptedStoragePlugin and CryptoPlugin
  interfaces.

  Plugin implementers must be aware that the information reporting methods
  (storageType(), encryptionType(), and encryptionAlgorithm()) will be invoked
  from the main thread of the secrets daemon, while the various interface
  operation methods will be invoked from a separate thread.  Plugins are loaded
  and plugin instances are constructed in the main thread.
 */

/*!
 * \brief Construct a new EncryptedStoragePlugin instance
 */
EncryptedStoragePlugin::EncryptedStoragePlugin()
    : PluginBase()
{
}

/*!
 * \brief Clean up any memory associated with the EncryptedStoragePlugin instance
 */
EncryptedStoragePlugin::~EncryptedStoragePlugin()
{
}

/*!
 * \fn EncryptedStoragePlugin::storageType() const
 * \brief Returns the type of storage which is exposed by the plugin
 */

/*!
 * \fn EncryptedStoragePlugin::encryptionType() const
 * \brief Returns the type of encryption capability offered by the plugin
 */

/*!
 * \fn EncryptedStoragePlugin::encryptionAlgorithm() const
 * \brief Returns the encryption algorithm which is used by the plugin
 */

/*!
 * \fn EncryptedStoragePlugin::collectionNames(QStringList *names)
 * \brief Writes the names of collections managed by the plugin to \a names
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::SecretsPluginIsLockedError.
 *
 * If the encrypted storage plugin supports storing collections of secrets,
 * it must implement this method by returning the names of currently
 * stored collections into the out-parameter \a names and returning
 * a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Succeeded.
 *
 * Otherwise, it should write an empty list of collection names to the
 * out-parameter \a names and return a Sailfish::Secrets::Result with
 * the result code set to Sailfish::Secrets::Result::Succeeded.
 *
 * If the operation failed due to storage backend failure, the plugin should
 * return a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Failed and the error code set to
 * Sailfish::Secrets::Result::DatabaseError.
 */

/*!
 * \fn EncryptedStoragePlugin::createCollection(const QString &collectionName, const QByteArray &key)
 * \brief Creates a collection encrypted with the given \a key within which to store secrets called \a collectionName
 *
 * The \a key is guaranteed to have been derived by this plugin, via a previous
 * call to \a deriveKeyFromCode().
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::SecretsPluginIsLockedError.
 *
 * If the storage plugin does not support the creation of new collections,
 * it should return a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::OperationNotSupportedError.
 *
 * If a collection with that name already exists in the storage managed
 * by the plugin, the plugin should return a Sailfish::Secrets::Result
 * with the result code set to Sailfish::Secrets::Result::Failed and the
 * error code set to Sailfish::Secrets::Result::CollectionAlreadyExistsError.
 *
 * If the encrypted storage plugin supports storing collections of secrets,
 * it must implement this method such that the new collection is created,
 * its name is subsequently returned from \l collectionNames(), and
 * secrets can be stored in it, and the plugin should return a
 * Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Succeeded.
 *
 * If the operation failed due to storage backend failure, the plugin should
 * return a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Failed and the error code set to
 * Sailfish::Secrets::Result::DatabaseError.
 */

/*!
 * \fn EncryptedStoragePlugin::removeCollection(const QString &collectionName)
 * \brief Removes the collection with the given \a collectionName from the
 *        storage managed by the plugin.
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::SecretsPluginIsLockedError.
 *
 * If the storage plugin does not support the removal of collections,
 * it should return a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::OperationNotSupportedError.
 *
 * If no collection with that name exists in the storage managed by the plugin,
 * the plugin should return a Sailfish::Secrets::Result
 * with the result code set to Sailfish::Secrets::Result::Failed and the
 * error code set to Sailfish::Secrets::Result::InvalidCollectionError.
 *
 * If the encryptedstorage plugin supports removing collections of secrets,
 * it must implement this method such that the specified collection is removed,
 * its name is subsequently no longer returned from \l collectionNames(), and
 * and the plugin should return a Sailfish::Secrets::Result with the result
 * code set to Sailfish::Secrets::Result::Succeeded.  Any secrets which were
 * stored into this collection should be removed as part of this operation.
 *
 * If the operation failed due to storage backend failure, the plugin should
 * return a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Failed and the error code set to
 * Sailfish::Secrets::Result::DatabaseError.
 */

/*!
 * \fn EncryptedStoragePlugin::isCollectionLocked(const QString &collectionName, bool *locked)
 * \brief Writes true to the out-parameter \a locked if the collection with
 *        the given \a collectionName is locked and needs to be unlocked via
 *        \l setEncryptionKey() before any data can be written to or read from
 *        it.
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::SecretsPluginIsLockedError.
 *
 * If no collection with that name exists in the storage managed by the plugin,
 * the plugin should return a Sailfish::Secrets::Result
 * with the result code set to Sailfish::Secrets::Result::Failed and the
 * error code set to Sailfish::Secrets::Result::InvalidCollectionError.
 *
 * Otherwise, the lock state of the collection should be written to the
 * \a locked out-parameter, and the plugin should return a
 * Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Succeeded.
 */

/*!
 * \fn EncryptedStoragePlugin::deriveKeyFromCode(const QByteArray &authenticationCode, const QByteArray &salt, QByteArray *key)
 * \brief Derive an encryption key valid for use in encryption and decryption
 *        operations offered by this plugin from the given \a authenticationCode
 *        and \a salt, and write it to the out-parameter \a key.
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::SecretsPluginIsLockedError.
 */

/*!
 * \fn EncryptedStoragePlugin::setEncryptionKey(const QString &collectionName, const QByteArray &key)
 * \brief Unlock the collection identified by the given \a collectionName
 *        using the specified encryption \a key.
 *
 * The \a key is guaranteed to have been derived by this plugin, via a previous
 * call to \a deriveKeyFromCode().
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::SecretsPluginIsLockedError.
 *
 * If the plugin does not support per-collection locks (or per-collection
 * encryption) but instead only supports plugin-global locking, the plugin
 * should return a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::OperationNotSupportedError.
 *
 * If the given \a key is correct, the collection should be able to be written
 * to and read from, and the plugin should return a Sailfish::Secrets::Result
 * with the result code set to Sailfish::Secrets::Result::Succeeded.
 *
 * Otherwise, if the \a key is incorrect, the plugin should lock the collection
 * if it was previous unlocked, and return a Sailfish::Secrets::Result
 * with the result code set to Sailfish::Secrets::Result::Succeeded, but
 * the new lock-state of the collection should be reflected in the
 * out-parameter result of subsequent calls to \l isCollectionLocked().
 */

/*!
 * \fn EncryptedStoragePlugin::reencrypt(const QString &collectionName, const QByteArray &oldkey, const QByteArray &newkey)
 * \brief Transactionally unlock the collection with the given
 *        \a collectionName with the given \a oldkey and then re-encrypt it
 *        with the specified \a newkey.
 *
 * The \a oldkey and the \a newkey are guaranteed to have been derived by
 * this plugin, via a previous call to \a deriveKeyFromCode().
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::SecretsPluginIsLockedError.
 *
 * If the plugin does not support per-collection locks (or per-collection
 * encryption) but instead only supports plugin-global locking, the plugin
 * should return a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::OperationNotSupportedError.
 *
 * If no collection with that name exists in the storage managed by the plugin,
 * the plugin should return a Sailfish::Secrets::Result
 * with the result code set to Sailfish::Secrets::Result::Failed and the
 * error code set to Sailfish::Secrets::Result::InvalidCollectionError.
 *
 * If the \a oldkey does not successfully unlock the collection then the
 * plugin should return a Sailfish::Secrets::Result with the result code set
 * to Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::CollectionIsLockedError.
 *
 * Otherwise the collection should be encrypted with the \a newkey and the
 * plugin should return a Sailfish::Secrets::Result with the result code set
 * to Sailfish::Secrets::Result::Succeeded.
 *
 * If the operation failed due to storage backend failure, the plugin should
 * return a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Failed and the error code set to
 * Sailfish::Secrets::Result::DatabaseError.
 */

/*!
 * \fn EncryptedStoragePlugin::setSecret(const QString &collectionName, const QString &secretName, const QByteArray &secret, const Sailfish::Secrets::Secret::FilterData &filterData)
 * \brief Store \a secret data identified by the given \a secretName with
 *        associated \a filterData into the collection identified by the
 *        given \a collectionName.
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::SecretsPluginIsLockedError.
 *
 * If no collection with that name exists in the storage managed by the plugin,
 * the plugin should return a Sailfish::Secrets::Result
 * with the result code set to Sailfish::Secrets::Result::Failed and the
 * error code set to Sailfish::Secrets::Result::InvalidCollectionError.
 *
 * If the collection identified by the given \a collectionName is locked then
 * the plugin should return a Sailfish::Secrets::Result with the result code
 * set to Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::CollectionIsLockedError.
 *
 * If a secret with the specified \a secretName is already stored
 * in the collection identified by the given \a collectionName, the plugin
 * should return a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::SecretAlreadyExistsError.
 *
 * Otherwise the \a secret and \a filterData for the secret with the given
 * \a secretName should be stored into the collection and the plugin should
 * return a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Succeeded.
 *
 * If the operation failed due to storage backend failure, the plugin should
 * return a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Failed and the error code set to
 * Sailfish::Secrets::Result::DatabaseError.
 */

/*!
 * \fn EncryptedStoragePlugin::getSecret(const QString &collectionName, const QString &secretName, QByteArray *secret, Sailfish::Secrets::Secret::FilterData *filterData)
 * \brief Retrieve the secret data and filter data for the secret identified
 *        by the given \a secretName from the collection identified by the
 *        given \a collectionName and write them to the \a secret and
 *        \a filterData out-parameters respectively.
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::SecretsPluginIsLockedError.
 *
 * If no collection with that name exists in the storage managed by the plugin,
 * the plugin should return a Sailfish::Secrets::Result
 * with the result code set to Sailfish::Secrets::Result::Failed and the
 * error code set to Sailfish::Secrets::Result::InvalidCollectionError.
 *
 * If the collection identified by the given \a collectionName is locked then
 * the plugin should return a Sailfish::Secrets::Result with the result code
 * set to Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::CollectionIsLockedError.
 *
 * If no secret identified by the given \a secretName exists within the
 * specified collection then the plugin should return a
 * Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::InvalidSecretError.
 *
 * Otherwise the \a secret and \a filterData for the secret with the given
 * \a secretName should be retrieved from the collection and the plugin should
 * return a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Succeeded.
 *
 * If the operation failed due to storage backend failure, the plugin should
 * return a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Failed and the error code set to
 * Sailfish::Secrets::Result::DatabaseError.
 */

/*!
 * \fn EncryptedStoragePlugin::secretNames(const QString &collectionName, QStringList *secretNames)
 * \brief Retrive the names of secrets stored in the collection identified
 *        by the given \a collectionName and write them to the out-parameter
 *        \a secretNames.
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::SecretsPluginIsLockedError.
 *
 * If no collection with that name exists in the storage managed by the plugin,
 * the plugin should return a Sailfish::Secrets::Result
 * with the result code set to Sailfish::Secrets::Result::Failed and the
 * error code set to Sailfish::Secrets::Result::InvalidCollectionError.
 *
 * If the collection identified by the given \a collectionName is locked then
 * the plugin should return a Sailfish::Secrets::Result with the result code
 * set to Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::CollectionIsLockedError.
 *
 * Otherwise the \a secretNames should be retrieved from the collection and
 * the plugin should return a Sailfish::Secrets::Result with the result code
 * set to Sailfish::Secrets::Result::Succeeded.
 *
 * If the operation failed due to storage backend failure, the plugin should
 * return a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Failed and the error code set to
 * Sailfish::Secrets::Result::DatabaseError.
 */

/*!
 * \fn EncryptedStoragePlugin::findSecrets(const QString &collectionName, const Sailfish::Secrets::Secret::FilterData &filter, Sailfish::Secrets::StoragePlugin::FilterOperator filterOperator, QVector<Sailfish::Secrets::Secret::Identifier> *identifiers)
 * \brief Retrieve the names of secrets in the collection identified by the
 *        given \a collectionName which match the given \a filter according
 *        to the specified \a filterOperator, and return them in the
 *        \a identifiers out-parameter.
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::SecretsPluginIsLockedError.
 *
 * If no collection with that name exists in the storage managed by the plugin,
 * the plugin should return a Sailfish::Secrets::Result
 * with the result code set to Sailfish::Secrets::Result::Failed and the
 * error code set to Sailfish::Secrets::Result::InvalidCollectionError.
 *
 * If the collection identified by the given \a collectionName is locked then
 * the plugin should return a Sailfish::Secrets::Result with the result code
 * set to Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::CollectionIsLockedError.
 *
 * Otherwise the secret names should be retrieved from the collection and
 * a vector of valid identifiers should be constructed and returned in the
 * out-parameter \a identifiers, and the plugin should return a
 * Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Succeeded.
 *
 * If the operation failed due to storage backend failure, the plugin should
 * return a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Failed and the error code set to
 * Sailfish::Secrets::Result::DatabaseError.
 */

/*!
 * \fn EncryptedStoragePlugin::removeSecret(const QString &collectionName, const QString &secretName)
 * \brief Remove the secret (and associated filter data) identified by the
 *        given \a secretName from the collection identified by the given
 *        \a collectionName.
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::SecretsPluginIsLockedError.
 *
 * If no collection with that name exists in the storage managed by the plugin,
 * the plugin should return a Sailfish::Secrets::Result
 * with the result code set to Sailfish::Secrets::Result::Failed and the
 * error code set to Sailfish::Secrets::Result::InvalidCollectionError.
 *
 * If the collection identified by the given \a collectionName is locked then
 * the plugin should return a Sailfish::Secrets::Result with the result code
 * set to Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::CollectionIsLockedError.
 *
 * If no standalone secret with the given \a secretName exists in the storage
 * managed by the plugin, the plugin should return a Sailfish::Secrets::Result
 * with the result code set to Sailfish::Secrets::Result::Failed and the
 * error code set to Sailfish::Secrets::Result::InvalidSecretError.
 *
 * Otherwise the secret with the given \a secretName should be removed from the
 * collection and the plugin should return a Sailfish::Secrets::Result with the
 * result code set to Sailfish::Secrets::Result::Succeeded.
 *
 * If the operation failed due to storage backend failure, the plugin should
 * return a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Failed and the error code set to
 * Sailfish::Secrets::Result::DatabaseError.
 */

/*!
 * \fn EncryptedStoragePlugin::setSecret(const QString &secretName, const QByteArray &secret, const Sailfish::Secrets::Secret::FilterData &filterData, const QByteArray &key)
 * \brief Store a standalone secret identified by the given \a secretName
 *        with the specified \a secret data and filter data \a filterData,
 *        encrypted with the specified encryption \a key.
 *
 * The \a key is guaranteed to have been derived by this plugin, via a previous
 * call to \a deriveKeyFromCode().
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::SecretsPluginIsLockedError.
 *
 * If the storage plugin does not support storing standalone secrets,
 * it should return a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::OperationNotSupportedError.
 *
 * If a standalone secret with the specified \a secretName is already stored
 * in the storage managed by the plugin, the plugin should return
 * a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::SecretAlreadyExistsError.
 *
 * Otherwise the \a secret and \a filterData for the secret with the
 * given \a secretName should be stored and the plugin should
 * return a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Succeeded.
 *
 * If the operation failed due to storage backend failure, the plugin should
 * return a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Failed and the error code set to
 * Sailfish::Secrets::Result::DatabaseError.
 */

/*!
 * \fn EncryptedStoragePlugin::accessSecret(const QString &secretName, const QByteArray &key, QByteArray *secret, Sailfish::Secrets::Secret::FilterData *filterData)
 * \brief Retrieve the standalone \a secret identified by the given
 *        \a secretName and decrypt it with the specified \a key,
 *        and also retrieve its associated \a filterData.
 *
 * The \a key is guaranteed to have been derived by this plugin, via a previous
 * call to \a deriveKeyFromCode().
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::SecretsPluginIsLockedError.
 *
 * If the storage plugin does not support storing standalone secrets,
 * it should return a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::OperationNotSupportedError.
 *
 * If no standalone secret with the specified \a secretName is stored
 * in the storage managed by the plugin, the plugin should return
 * a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::InvalidSecretError.
 *
 * Otherwise the \a secret and \a filterData for the secret with the
 * given \a secretName should be retrieved, the \a secret should be
 * decrypted with the given \a key, and the plugin should
 * return a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Succeeded.
 *
 * If the operation failed due to storage backend failure, the plugin should
 * return a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Failed and the error code set to
 * Sailfish::Secrets::Result::DatabaseError.
 */

/*!
 * \fn EncryptedStoragePlugin::removeSecret(const QString &secretName)
 * \brief Remove the standalone secret identified by the given \a secretName
 *        along with any associated filter data.
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::SecretsPluginIsLockedError.
 *
 * If the storage plugin does not support storing standalone secrets,
 * it should return a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::OperationNotSupportedError.
 *
 * Otherwise the secret and filter data for the secret with the
 * given \a secretName should be removed from the storage managed
 * by the plugin, and the plugin should return a Sailfish::Secrets::Result
 * with the result code set to Sailfish::Secrets::Result::Succeeded.
 *
 * If the operation failed due to storage backend failure, the plugin should
 * return a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Failed and the error code set to
 * Sailfish::Secrets::Result::DatabaseError.
 */

/*!
 * \fn EncryptedStoragePlugin::reencryptSecret(const QString &secretName, const QByteArray &oldkey, const QByteArray &newkey)
 * \brief Reencrypt the standalone secret with the specified \a secretName
 *        with the given \a newkey after decrypting it with the given
 *        \a oldkey.
 *
 * Both the \a newkey and the \a oldkey are guaranteed to have been derived
 * by this plugin, via previous calls to \a deriveKeyFromCode().
 *
 * Only the secret data (and not the filter data) should be re-encrypted.
 *
 * This method will be invoked if the user changes the master encryption key,
 * if any standalone secret stored within this storage plugin uses master-lock
 * (or device-lock) semantics.  It will also be invoked if the user changes
 * a custom-lock associated with a standalone secret.
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::SecretsPluginIsLockedError.
 *
 * If the storage plugin does not support storing standalone secrets,
 * it should return a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::OperationNotSupportedError.
 *
 * If no standalone secret with that name exists in the storage managed by the
 * plugin, the plugin should return a Sailfish::Secrets::Result
 * with the result code set to Sailfish::Secrets::Result::Failed and the
 * error code set to Sailfish::Secrets::Result::InvalidSecretError.
 *
 * If the \a oldkey does not successfully decrypt the secret data then the
 * plugin should return a Sailfish::Secrets::Result with the result code set
 * to Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::SecretsPluginDecryptionError.
 *
 * If the secret data was re-encrypted and updated within storage successfully,
 * the plugin should return a Sailfish::Secrets::Result with the result code
 * set to Sailfish::Secrets::Result::Succeeded.
 *
 * If the operation failed due to storage backend failure, the plugin should
 * return a Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Failed and the error code set to
 * Sailfish::Secrets::Result::DatabaseError.
 */


/*!
  \class AuthenticationPlugin
  \brief Specifies an interface allowing verification of a user's identity,
         retrieval of an authentication code or passphrase from a user,
         or both.

  The AuthenticationPlugin type specifies an interface which includes
  operations to verify the identity of a user and to retrieve authentication
  codes from the user (from which encryption keys may be derived).

  All methods provided by AuthenticationPlugin-derived types are invoked
  from the main thread of the secrets daemon, and thus care should be taken
  to avoid blocking.
 */

/*!
 * \enum AuthenticationPlugin::AuthenticationType
 *
 * This enum defines the types of authentication offered by the plugin
 *
 * \value NoAuthentication No authentication, flows requiring authentication data will fail.
 * \value ApplicationSpecificAuthentication Unknown type, application generates auth code based on custom UI flow.
 * \value SystemDefaultAuthentication User enters some authentication data, as required by the system, to authenticate.
 * \value PinCodeAuthentication User enters a pin code as the authentication method
 * \value PasswordAuthentication User enters a password as the authentication method
 * \value FingerprintAuthentication User scans their fingerprint as the authentication method
 * \value IrisScanAuthentication User scans their iris as the authentication method
 * \value VoiceRecognitionAuthentication User performs voice recognition as the authentication method
 */

/*!
 * \fn AuthenticationPlugin::authenticationTypes() const
 * \brief Return the types of authentication which are supported by this plugin
 *
 * These are the ways in which the user's identity may be verificationStatus.
 */

/*!
 * \brief Construct a new AuthenticationPlugin instance with the specified \a parent
 */
AuthenticationPlugin::AuthenticationPlugin(QObject *parent)
    : QObject(parent)
{
}

/*!
 * \brief Clean up the memory associated with the AuthenticationPlugin instance
 */
AuthenticationPlugin::~AuthenticationPlugin()
{
}

/*!
 * \fn AuthenticationPlugin::inputTypes() const
 * \brief Return the types of data which the plugin can return after retrieval from the user
 *
 * These are the types of data which may be returned after user input interaction.
 */

/*!
 * \fn AuthenticationPlugin::beginAuthentication(uint pid, qint64 requestId)
 * \brief Begin an authentication (user verification) flow on behalf of the
 *        application with the specified \a pid as part of the secrets
 *        framework request with the specified \a requestId.
 *
 * This will be invoked if an application is attempting to perform some
 * operation on a device-locked collection or secret, where the device
 * lock key is known by the secrets daemon but the user must verify
 * in order to allow the secrets daemon to unlock the collection or
 * secret with the known device lock key.
 *
 * When complete, the plugin should emit the authenticationCompleted()
 * signal, with the result parameter having the appropriate result code
 * set depending on whether the user successfully verificationStatus their identity
 * or not.
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::SecretsPluginIsLockedError.
 */

/*!
 * \fn AuthenticationPlugin::beginUserInputInteraction(uint pid, qint64 requestId, const Sailfish::Secrets::InteractionParameters &interactionParameters, const QString &interactionServiceAddress)
 * \brief Begin a user input interaction flow on behalf of the application
 *        with the specified \a pid as part of the secrets framework request
 *        with the specified \a requestId, according to the specified
 *        \a interactionParameters, potentially using the in-app
 *        interaction service with the specified \a interactionServiceAddress.
 *
 * If the plugin implements application-specific authentication (that is,
 * allows the application to perform the user verification or user input
 * flow in-process) then it should delegate the operation to the service
 * whose (peer to peer) DBus address is given as \a interactionServiceAddress.
 * Otherwise, the \a interactionServiceAddress parameter should be ignored.
 *
 * The \a interactionParameters will contain a variety of parameters which
 * specify the type of input which is wanted from the user, as well as the
 * look and feel of any user interaction prompt which is required (e.g.
 * the echo mode of input characters, etc).
 *
 * When complete, the plugin should emit the userInputInteractionCompleted()
 * signal, with the result parameter having an appropriate result code set
 * and the user's input provided.
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Secrets::Result with the result code set to
 * Sailfish::Secrets::Result::Failed and the error code set to
 * Sailfish::Secrets::Result::SecretsPluginIsLockedError.
 */
