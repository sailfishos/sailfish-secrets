/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Crypto/Plugins/extensionplugins.h"

#include <Crypto/key.h>

#include <QtCore/QMap>
#include <QtCore/QVector>
#include <QtCore/QString>

SAILFISH_CRYPTO_API Q_LOGGING_CATEGORY(lcSailfishCryptoPlugin, "org.sailfishos.crypto.daemon.plugin", QtWarningMsg)

using namespace Sailfish::Crypto;

/*!
  \class CryptoPlugin
  \brief Specifies an interface which provides a variety of cryptographic
         operations to clients which will be exposed via the Sailfish OS
         Crypto API.

  The CryptoPlugin type specifies an interface which provides encryption,
  decryption, signing, verification, key derivation, key pair generation,
  random data generation, and digest calculation.

  The interface also includes methods related to key storage and retrieval,
  for those plugins which include external key storage capability (which
  offers the maximum security for stored keys as they need never be pulled
  into the secrets daemon process address space).  Note that if a plugin
  implements these methods, it must also implement the
  Sailfish::Secrets::EncryptedStoragePlugin interface from the Sailfish OS
  Secrets Extension Plugin API.  Any plugin which implements both of these
  interfaces is known as a Crypto Storage Plugin (for an example of such a
  plugin, please see the ExampleUsbTokenPlugin in the source tree).

  Plugin implementers must be aware that the information reporting methods
  (encryptionType(), and canStoreKeys()) will be invoked from the main
  thread of the secrets daemon, while the various interface operation methods
  will be invoked from a separate thread.  Plugins are loaded and plugin
  instances are constructed in the main thread.

  In order to implement a Crypto extension plugin, plugin implementers should
  specify the following in their .pro file:
  \code
  CONFIG += link_pkgconfig
  PKGCONFIG += sailfishcryptopluginapi
  \endcode

  The CryptoPlugin class extends the Sailfish::Secrets::PluginBase abstract
  base class, and the sailfishcryptopluginapi pkgconfig file will entail
  a dependency upon sailfishsecretspluginapi and sailfishsecrets, as
  well as sailfishcrypto.

  An example (skeleton) Crypto plugin without key storage capability may be
  found at: https://github.com/sailfishos/sailfish-secrets/tree/master/examples/plugins/examplecryptoplugin/

  An example (skeleton) Crypto Storage plugin may be found at:
  https://github.com/sailfishos/sailfish-secrets/tree/master/examples/plugins/examplecryptostorageplugin/
 */

/*!
 * \enum CryptoPlugin::EncryptionType
 *
 * This enum defines the types of encryption capability which may be offered by plugins
 *
 * \value NoEncryption No encryption is performed
 * \value SoftwareEncryption Encryption is performed by "normal" rich execution environment application
 * \value TrustedExecutionSoftwareEncryption Encryption is performed by trusted execution environment (TEE) application
 * \value SecurePeripheralEncryption Encryption is performed by a secure element (SE) hardware peripheral via TEE application
 */

/*!
 * \brief Construct a new CryptoPlugin instance
 */
CryptoPlugin::CryptoPlugin()
{
}

/*!
 * \brief Clean up any memory associated with the CryptoPlugin instance
 */
CryptoPlugin::~CryptoPlugin()
{
}

/*!
 * \fn CryptoPlugin::canStoreKeys() const
 * \brief Returns true if the plugin can store keys
 *
 * If the plugin either exposes some built-in keys (e.g. as in the case of
 * a USB-token-backed plugin) or allows the creation and storage of new keys
 * (e.g. as in the case of an online-service-backed plugin), it should
 * return true from this method and also must implement the
 * Sailfish::Secrets::EncryptedStoragePlugin interface.
 */

/*!
 * \fn CryptoPlugin::encryptionType() const
 * \brief Returns the type of encryption capability offered by the plugin
 */

/*!
 * \fn CryptoPlugin::generateRandomData(quint64 callerIdent, const QString &csprngEngineName, quint64 numberBytes, const QVariantMap &customParameters, QByteArray *randomData)
 * \brief Writes \a numberBytes of random data generated using the random
 *        number generator identified by the specified \a csprngEngineName
 *        into \a randomData for the caller identified by the given
 *        \a callerIdent.
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Result::Failed and the error code set to
 * Sailfish::Crypto::Result::CryptoPluginIsLockedError.
 *
 * The \a customParameters will contain plugin-specific parameters which may
 * be required by the plugin.  Such parameters must be documented for clients
 * in the documentation provided with the plugin, and otherwise should be
 * ignored by plugin implementers.
 */

/*!
 * \fn CryptoPlugin::seedRandomDataGenerator(quint64 callerIdent, const QString &csprngEngineName, const QByteArray &seedData, double entropyEstimate, const QVariantMap &customParameters)
 * \brief Seed the random number generator identified by the given
 *        \a csprngEngineName with the given \a seedData assuming
 *        the specified \a entropyEstimate for the caller identified
 *        by the given \a callerIdent.
 *
 * The entropy estimate should be between clamped 0.0 and 1.0.
 *
 * This operation should be implemented in such a way that it will not affect
 * clients other than the client identified by the \a callerIdent.
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Result::Failed and the error code set to
 * Sailfish::Crypto::Result::CryptoPluginIsLockedError.
 *
 * The \a customParameters will contain plugin-specific parameters which may
 * be required by the plugin.  Such parameters must be documented for clients
 * in the documentation provided with the plugin, and otherwise should be
 * ignored by plugin implementers.
 */

/*!
 * \fn CryptoPlugin::generateInitializationVector(Sailfish::Crypto::CryptoManager::Algorithm algorithm, Sailfish::Crypto::CryptoManager::BlockMode blockMode, int keySize, const QVariantMap &customParameters, QByteArray *generatedIV)
 * \brief Write an appropriate (randomly generated) initialization vector
 *        for use with encryption and decryption operations based on the
 *        specified \a algorithm, \a blockMode and \a keySize into
 *        \a generatedIV.
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Result::Failed and the error code set to
 * Sailfish::Crypto::Result::CryptoPluginIsLockedError.
 *
 * The \a customParameters will contain plugin-specific parameters which may
 * be required by the plugin.  Such parameters must be documented for clients
 * in the documentation provided with the plugin, and otherwise should be
 * ignored by plugin implementers.
 */

/*!
 * \fn CryptoPlugin::generateKey(const Sailfish::Crypto::Key &keyTemplate, const Sailfish::Crypto::KeyPairGenerationParameters &kpgParams, const Sailfish::Crypto::KeyDerivationParameters &skdfParams, const QVariantMap &customParameters, Sailfish::Crypto::Key *key)
 * \brief Generates a key based on the given \a keyTemplate as well as either
 *        the given key-pair generation parameters \a kpgParams or the given
 *        symmetric key derivation function parameters \a skdfParams and writes
 *        it to the out-parameter \a key.
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Result::Failed and the error code set to
 * Sailfish::Crypto::Result::CryptoPluginIsLockedError.
 *
 * The \a customParameters will contain plugin-specific parameters which may
 * be required by the plugin.  Such parameters must be documented for clients
 * in the documentation provided with the plugin, and otherwise should be
 * ignored by plugin implementers.
 *
 * If the given key pair generation parameters \a kpgParams are valid, then
 * those parameters specify the security size of the key (i.e. modulus length),
 * and the algorithm (according to the key pair type).  The algorithm specified
 * in the \a keyTemplate should be consistent with the algorithm associated
 * with the key pair type specified in the key pair generation parameters,
 * otherwise the plugin should return a Sailfish::Crypto::Result with the
 * result code set to Sailfish::Crypto::Result::Failed and the error code set
 * to Sailfish::Crypto::Result::CryptoPluginKeyGenerationError.
 *
 * Otherwise, if the key derivation parameters \a skdfParams are valid, then
 * those parameters specify the security size of the key (i.e. the output
 * key size), while the \a keyTemplate specifies the algorithm for the output
 * key.
 *
 * If neither the key pair generation parameters nor key derivation parameters
 * are valid, then the plugin should generate a key appropriate for use with
 * the algorithm specified in the \a keyTemplate, whose security size is
 * that specified in the \a keyTemplate.
 *
 * The out-parameter \a key should include all key data, including private
 * and secret key data, as well as the filter data which was specified in
 * the \a keyTemplate, and it should have its algorithm and size set
 * appropriately.
 */

/*!
 * \fn CryptoPlugin::generateAndStoreKey(const Sailfish::Crypto::Key &keyTemplate, const Sailfish::Crypto::KeyPairGenerationParameters &kpgParams, const Sailfish::Crypto::KeyDerivationParameters &skdfParams, const QVariantMap &customParameters, Sailfish::Crypto::Key *keyMetadata)
 * \brief Generates a key based on the given \a keyTemplate as well as either
 *        the given key-pair generation parameters \a kpgParams or the given
 *        symmetric key derivation function parameters \a skdfParams and stores
 *        the generated key into key storage managed by the plugin, and writing
 *        a reference to that key to the out-parameter \a keyMetadata.
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Result::Failed and the error code set to
 * Sailfish::Crypto::Result::CryptoPluginIsLockedError.
 *
 * The \a customParameters will contain plugin-specific parameters which may
 * be required by the plugin.  Such parameters must be documented for clients
 * in the documentation provided with the plugin, and otherwise should be
 * ignored by plugin implementers.
 *
 * If the given key pair generation parameters \a kpgParams are valid, then
 * those parameters specify the security size of the key (i.e. modulus length),
 * and the algorithm (according to the key pair type).  The algorithm specified
 * in the \a keyTemplate should be consistent with the algorithm associated
 * with the key pair type specified in the key pair generation parameters,
 * otherwise the plugin should return a Sailfish::Crypto::Result with the
 * result code set to Sailfish::Crypto::Result::Failed and the error code set
 * to Sailfish::Crypto::Result::CryptoPluginKeyGenerationError.
 *
 * Otherwise, if the key derivation parameters \a skdfParams are valid, then
 * those parameters specify the security size of the key (i.e. the output
 * key size), while the \a keyTemplate specifies the algorithm for the output
 * key.
 *
 * If neither the key pair generation parameters nor key derivation parameters
 * are valid, then the plugin should generate a key appropriate for use with
 * the algorithm specified in the \a keyTemplate, whose security size is
 * that specified in the \a keyTemplate.
 *
 * The out-parameter \a keyMetadata should include only key metadata as well as
 * public key data, but not private or secret key data.  It should include the
 * filter data which was specified in the \a keyTemplate, and it should have
 * its algorithm and size set appropriately.  Its identifier should be set to
 * that of the \a keyTemplate.
 *
 * The key template will contain an identifier which specifies the name of the
 * collection into which the generated key should be stored, and also the name
 * of the key in that collection.
 *
 * If the collection name specified in the identifier of the \a keyTemplate
 * does not specify a valid collection managed by the plugin, the plugin
 * should return a Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Failed and the error code set to
 * Sailfish::Crypto::Result::InvalidKeyIdentifier and the storage error code
 * set to Sailfish::Secrets::Result::InvalidCollectionError.
 *
 * If the secret name specified in the identifier of the \a keyTemplate
 * duplicates an existing key or secret in the same collection identified by
 * the collection name specified in the identifier of the \a keyTemplate, the
 * plugin should return a Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Failed and the error code set to
 * Sailfish::Crypto::Result::InvalidKeyIdentifier and the storage error code
 * set to Sailfish::Secrets::Result::SecretAlreadyExistsError.
 *
 * If the plugin does not support storing new keys, it should return a
 * Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Failed and the error code set to
 * Sailfish::Crypto::Result::OperationNotSupportedError.
 *
 * If the operation failed due to storage backend failure, the plugin should
 * return a Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Failed and the error code set to
 * Sailfish::Crypto::Result::StorageError and the storage error code
 * set to Sailfish::Secrets::Result::DatabaseError.
 *
 * Otherwise, the plugin should return a Sailfish::Crypto::Result with
 * the result code set to Sailfish::Crypto::Result::Succeeded.
 */

/*!
 * \fn CryptoPlugin::importKey(const QByteArray &data, const QByteArray &passphrase, const QVariantMap &customParameters, Sailfish::Crypto::Key *importedKey)
 * \brief Imports the serialized key data of the given \a data and generates
 *        a fully specified and usable key, which is written to the out-parameter
 *        \a importedKey. The interpretation of the serialized data is left
 *        to the plugin to be interpreted.
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Result::Failed and the error code set to
 * Sailfish::Crypto::Result::CryptoPluginIsLockedError.
 *
 * The \a customParameters will contain plugin-specific parameters which may
 * be required by the plugin.  Such parameters must be documented for clients
 * in the documentation provided with the plugin, and otherwise should be
 * ignored by plugin implementers.
 *
 * The serialized key data may require a passphrase to import, in which case
 * the plugin should attempt to use the specified \a passphrase.  If that
 * passphrase fails to decrypt the key content, the plugin should return a
 * Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Result::Failed and the error code set to
 * Sailfish::Crypto::Result::CryptoPluginIncorrectPassphrase.
 */

/*!
 * \fn CryptoPlugin::importAndStoreKey(const QByteArray &data, const Sailfish::Crypto::Key &keyTemplate, const QByteArray &passphrase, const QVariantMap &customParameters, Sailfish::Crypto::Key *keyMetadata)
 * \brief Imports the serialized key data of the given \a data and generates a fully
 *        specified and usable key, which is stored to the key storage managed
 *        by the plugin, and a reference to that key is written to the
 *        out-parameter \a keyMetadata. The identification of the newly imported
 *        key is defined in \a keyTemplate.
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Result::Failed and the error code set to
 * Sailfish::Crypto::Result::CryptoPluginIsLockedError.
 *
 * The \a customParameters will contain plugin-specific parameters which may
 * be required by the plugin.  Such parameters must be documented for clients
 * in the documentation provided with the plugin, and otherwise should be
 * ignored by plugin implementers.
 *
 * The serialized key data may require a passphrase to import, in which case
 * the plugin should attempt to use the specified \a passphrase.  If that
 * passphrase fails to decrypt the key content, the plugin should return a
 * Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Result::Failed and the error code set to
 * Sailfish::Crypto::Result::CryptoPluginIncorrectPassphrase.
 *
 * The out-parameter \a keyMetadata should include only key metadata (such as
 * its algorithm, size, and its full identifier) as well as public key data,
 * but not private or secret key data.
 *
 * If the collection name specified in the identifier of the \a keyTemplate
 * does not specify a valid collection managed by the plugin, the plugin
 * should return a Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Failed and the error code set to
 * Sailfish::Crypto::Result::InvalidKeyIdentifier and the storage error code
 * set to Sailfish::Secrets::Result::InvalidCollectionError.
 *
 * If the secret name specified in the identifier of the \a keyTemplate
 * duplicates an existing key or secret in the same collection identified by
 * the collection name specified in the identifier of the \a keyTemplate, the
 * plugin should return a Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Failed and the error code set to
 * Sailfish::Crypto::Result::InvalidKeyIdentifier and the storage error code
 * set to Sailfish::Secrets::Result::SecretAlreadyExistsError.
 *
 * If the plugin does not support storing new keys, it should return a
 * Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Failed and the error code set to
 * Sailfish::Crypto::Result::OperationNotSupportedError.
 *
 * If the operation failed due to storage backend failure, the plugin should
 * return a Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Failed and the error code set to
 * Sailfish::Crypto::Result::StorageError and the storage error code
 * set to Sailfish::Secrets::Result::DatabaseError.
 *
 * Otherwise, the plugin should return a Sailfish::Crypto::Result with
 * the result code set to Sailfish::Crypto::Result::Succeeded.
 */

/*!
 * \fn CryptoPlugin::storedKey(const Sailfish::Crypto::Key::Identifier &identifier, Sailfish::Crypto::Key::Components keyComponents, const QVariantMap &customParameters, Sailfish::Crypto::Key *key)
 * \brief Retrieve the key identified by the specified \a identifier limited
 *        to those components specified in \a keyComponents and write it
 *        to the out-parameter \a key.
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Result::Failed and the error code set to
 * Sailfish::Crypto::Result::CryptoPluginIsLockedError.
 *
 * The \a customParameters will contain plugin-specific parameters which may
 * be required by the plugin.  Such parameters must be documented for clients
 * in the documentation provided with the plugin, and otherwise should be
 * ignored by plugin implementers.
 *
 * If the collection name specified in the \a identifier
 * does not specify a valid collection managed by the plugin, the plugin
 * should return a Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Failed and the error code set to
 * Sailfish::Crypto::Result::InvalidKeyIdentifier and the storage error code
 * set to Sailfish::Secrets::Result::InvalidCollectionError.
 *
 * If the secret name specified in the \a identifier does not identify an
 * existing key or secret in the collection specified in the \a identifier,
 * the plugin should return a Sailfish::Crypto::Result with the result code
 * set to Sailfish::Crypto::Failed and the error code set to
 * Sailfish::Crypto::Result::InvalidKeyIdentifier and the storage error code
 * set to Sailfish::Secrets::Result::InvalidSecretError.
 *
 * If the plugin does not support retrieving key data, it should return a
 * Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Failed and the error code set to
 * Sailfish::Crypto::Result::OperationNotSupportedError.
 *
 * If the operation failed due to storage backend failure, the plugin should
 * return a Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Failed and the error code set to
 * Sailfish::Crypto::Result::StorageError and the storage error code
 * set to Sailfish::Secrets::Result::DatabaseError.
 *
 * Otherwise, the plugin should return a Sailfish::Crypto::Result with
 * the result code set to Sailfish::Crypto::Result::Succeeded.
 */

/*!
 * \fn CryptoPlugin::storedKeyIdentifiers(const QString &collectionName, const QVariantMap &customParameters, QVector<Sailfish::Crypto::Key::Identifier> *identifiers)
 * \brief Writes the identifiers of all keys stored by the plugin in the
 *        collection identified by the given \a collectionName into the
 *        out-parameter \a identifiers.
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Result::Failed and the error code set to
 * Sailfish::Crypto::Result::CryptoPluginIsLockedError.
 *
 * The \a customParameters will contain plugin-specific parameters which may
 * be required by the plugin.  Such parameters must be documented for clients
 * in the documentation provided with the plugin, and otherwise should be
 * ignored by plugin implementers.
 *
 * If the given \a collectionName does not specify a valid collection managed
 * by the plugin, or is empty, the plugin should return a
 * Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Failed and the error code set to
 * Sailfish::Crypto::Result::StorageError and the storage error code
 * set to Sailfish::Secrets::Result::InvalidCollectionError.
 *
 * If the operation failed due to storage backend failure, the plugin should
 * return a Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Failed and the error code set to
 * Sailfish::Crypto::Result::StorageError and the storage error code
 * set to Sailfish::Secrets::Result::DatabaseError.
 *
 * Otherwise, the plugin should return a Sailfish::Crypto::Result with
 * the result code set to Sailfish::Crypto::Result::Succeeded.
 */

/*!
 * \fn CryptoPlugin::calculateDigest(const QByteArray &data, Sailfish::Crypto::CryptoManager::SignaturePadding padding, Sailfish::Crypto::CryptoManager::DigestFunction digestFunction, const QVariantMap &customParameters, QByteArray *digest)
 * \brief Calculates a digest of the input message \a data using the specified
 *        \a padding according to the specified \a digestFunction, and writes
 *        the result hash to the \a digest out-parameter.
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Result::Failed and the error code set to
 * Sailfish::Crypto::Result::CryptoPluginIsLockedError.
 *
 * The \a customParameters will contain plugin-specific parameters which may
 * be required by the plugin.  Such parameters must be documented for clients
 * in the documentation provided with the plugin, and otherwise should be
 * ignored by plugin implementers.
 *
 * If the plugin does not support the specified \a digestFunction, it should
 * return a Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Result::Failed and the error code set to
 * Sailfish::Crypto::Result::DigestNotSupportedError.
 *
 * If the plugin does not support the specified \a padding, it should return a
 * Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Result::Failed and the error code set to
 * Sailfish::Crypto::Result::SignaturePaddingNotSupportedError.
 */

/*!
 * \fn CryptoPlugin::sign(const QByteArray &data, const Sailfish::Crypto::Key &key, Sailfish::Crypto::CryptoManager::SignaturePadding padding, Sailfish::Crypto::CryptoManager::DigestFunction digestFunction, const QVariantMap &customParameters, QByteArray *signature)
 * \brief Generates a signature for the input \a data using the specified
 *        \a padding according to the specified \a digestFunction with the
 *        given \a key and writes the result to the \a signature out-parameter.
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Result::Failed and the error code set to
 * Sailfish::Crypto::Result::CryptoPluginIsLockedError.
 *
 * The \a customParameters will contain plugin-specific parameters which may
 * be required by the plugin.  Such parameters must be documented for clients
 * in the documentation provided with the plugin, and otherwise should be
 * ignored by plugin implementers.
 *
 * If the plugin does not support the specified \a digestFunction, it should
 * return a Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Result::Failed and the error code set to
 * Sailfish::Crypto::Result::DigestNotSupportedError.
 *
 * If the plugin does not support the specified \a padding, it should return a
 * Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Result::Failed and the error code set to
 * Sailfish::Crypto::Result::SignaturePaddingNotSupportedError.
 *
 * The \a key may be either a full key (that is, containing private or secret
 * key data) which may be directly used to perform the data signing operation,
 * or it may be a key reference (that is, containing only metadata, including
 * an identifier) in which case (if it is a reference to a valid key stored
 * by the plugin) the full key it identifies should be retrieved from storage
 * and used to perform the operation.
 */

/*!
 * \fn CryptoPlugin::verify(const QByteArray &signature, const QByteArray &data, const Sailfish::Crypto::Key &key, Sailfish::Crypto::CryptoManager::SignaturePadding padding, Sailfish::Crypto::CryptoManager::DigestFunction digestFunction, const QVariantMap &customParameters, int *verificationStatus)
 * \brief Attempts to verify that the given \a signature was generated from the
 *        input \a data after being padded according to the \a padding, using
 *        the specified \a digestFunction and signing key \a key, and writes
 *        verification state to the out-parameter \a verificationStatus.
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Result::Failed and the error code set to
 * Sailfish::Crypto::Result::CryptoPluginIsLockedError.
 *
 * The \a customParameters will contain plugin-specific parameters which may
 * be required by the plugin.  Such parameters must be documented for clients
 * in the documentation provided with the plugin, and otherwise should be
 * ignored by plugin implementers.
 *
 * If the plugin does not support the specified \a digestFunction, it should
 * return a Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Result::Failed and the error code set to
 * Sailfish::Crypto::Result::DigestNotSupportedError.
 *
 * If the plugin does not support the specified \a padding, it should return a
 * Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Result::Failed and the error code set to
 * Sailfish::Crypto::Result::SignaturePaddingNotSupportedError.
 *
 * The \a key may be either a full key (that is, containing private or secret
 * key data) which may be directly used to perform the signature verification
 * operation, or it may be a key reference (that is, containing only metadata,
 * including an identifier) in which case (if it is a reference to a valid key
 * stored by the plugin) the full key it identifies should be retrieved from
 * storage and used to perform the operation.
 *
 * If the plugin was able to successfully determine that the given \a signature
 * was generated from the input \a data with the specified \a key then it
 * should write Sailfish::Crypto::CryptoManager::VerificationSucceeded to the
 * \a verificationStatus out-parameter and return a Sailfish::Crypto::Result with the
 * result code set to Sailfish::Crypto::Result::Succeeded.
 *
 * If the plugin was able to determine that the given \a signature was not
 * generated from the input \a data with the specified \a key then it
 * should write the appropriate Sailfish::Crypto::CryptoManager::VerificationStatus
 * value to the \a verificationStatus out-parameter and return a Sailfish::Crypto::Result
 * with the result code set to Sailfish::Crypto::Result::Succeeded (as it was
 * successfully able to determine that the signature was not correct).
 */

/*!
 * \fn CryptoPlugin::encrypt(const QByteArray &data, const QByteArray &iv, const Sailfish::Crypto::Key &key, Sailfish::Crypto::CryptoManager::BlockMode blockMode, Sailfish::Crypto::CryptoManager::EncryptionPadding padding, const QByteArray &authenticationData, const QVariantMap &customParameters, QByteArray *encrypted, QByteArray *authenticationTag)
 * \brief Encrypt the input \a data given an initialization vector \a iv using
 *        the specified \a key and (if applicable) \a blockMode and \a padding,
 *        and write the encrypted data to the out-parameter \a encrypted.
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Result::Failed and the error code set to
 * Sailfish::Crypto::Result::CryptoPluginIsLockedError.
 *
 * The \a customParameters will contain plugin-specific parameters which may
 * be required by the plugin.  Such parameters must be documented for clients
 * in the documentation provided with the plugin, and otherwise should be
 * ignored by plugin implementers.
 *
 * If the specified \a blockMode is an authenticated mode (such as GCM)
 * then the client should also have provided \a authenticationData, and upon
 * successfully encrypting the input \a data the plugin should also write the
 * generated authentication tag to the out-parameter \a authenticationTag.
 *
 * The \a key may be either a full key (that is, containing private or secret
 * key data) which may be directly used to perform the encryption operation,
 * or it may be a key reference (that is, containing only metadata, including
 * an identifier) in which case (if it is a reference to a valid key stored
 * by the plugin) the full key it identifies should be retrieved from storage
 * and used to perform the operation.
 */

/*!
 * \fn CryptoPlugin::decrypt(const QByteArray &data, const QByteArray &iv, const Sailfish::Crypto::Key &key, Sailfish::Crypto::CryptoManager::BlockMode blockMode, Sailfish::Crypto::CryptoManager::EncryptionPadding padding, const QByteArray &authenticationData, const QByteArray &authenticationTag, const QVariantMap &customParameters, QByteArray *decrypted, Sailfish::Crypto::CryptoManager::VerificationStatus *verificationStatus)
 * \brief Decrypt the input \a data given an initialization vector \a iv using
 *        the specified \a key and (if applicable) \a blockMode and \a padding,
 *        and write the decrypted data to the out-parameter \a decrypted.
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Result::Failed and the error code set to
 * Sailfish::Crypto::Result::CryptoPluginIsLockedError.
 *
 * The \a customParameters will contain plugin-specific parameters which may
 * be required by the plugin.  Such parameters must be documented for clients
 * in the documentation provided with the plugin, and otherwise should be
 * ignored by plugin implementers.
 *
 * If the specified \a blockMode is an authenticated mode (such as GCM)
 * then the client should also have provided \a authenticationData, and upon
 * successfully decrypting the input \a data the plugin should also calculate
 * the authentication tag and compare it to the given \a authenticationTag to
 * see if it matches, and should write the comparison result to the
 * \a verificationStatus out-parameter.  Note that if the decryption succeeded but the
 * authentication tag comparison failed, the result of the operation should
 * still be Sailfish::Crypto::Result::Succeeded, but clients are required to
 * explicitly check the value of the \a verificationStatus out-parameter to determine
 * whether the input data had been tampered with by an attacker.
 *
 * The \a key may be either a full key (that is, containing private or secret
 * key data) which may be directly used to perform the decryption operation,
 * or it may be a key reference (that is, containing only metadata, including
 * an identifier) in which case (if it is a reference to a valid key stored
 * by the plugin) the full key it identifies should be retrieved from storage
 * and used to perform the operation.
 */

/*!
 * \fn CryptoPlugin::initializeCipherSession(quint64 clientId, const QByteArray &iv, const Sailfish::Crypto::Key &key, Sailfish::Crypto::CryptoManager::Operation operation, Sailfish::Crypto::CryptoManager::BlockMode blockMode, Sailfish::Crypto::CryptoManager::EncryptionPadding encryptionPadding, Sailfish::Crypto::CryptoManager::SignaturePadding signaturePadding, Sailfish::Crypto::CryptoManager::DigestFunction digestFunction, const QVariantMap &customParameters, quint32 *cipherSessionToken)
 * \brief Initialize a new cipher session for the client identified by the
 *        given \a clientId, with the initialization vector \a iv and key
 *        \a key, to perform the specified \a operation, using the given
 *        \a blockMode, \a encryptionPadding and \a signaturePadding (if
 *        applicable), and digest function \a digestFunction, and write
 *        a token to track the cipher session to the out-parameter
 *        \a cipherSessionToken.
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Result::Failed and the error code set to
 * Sailfish::Crypto::Result::CryptoPluginIsLockedError.
 *
 * The \a customParameters will contain plugin-specific parameters which may
 * be required by the plugin.  Such parameters must be documented for clients
 * in the documentation provided with the plugin, and otherwise should be
 * ignored by plugin implementers.
 *
 * The \a key may be either a full key (that is, containing private or secret
 * key data) which may be directly used to perform the cipher operation,
 * or it may be a key reference (that is, containing only metadata, including
 * an identifier) in which case (if it is a reference to a valid key stored
 * by the plugin) the full key it identifies should be retrieved from storage
 * and used to perform the operation.
 *
 * Depending on the type of \a operation the client wishes to perform, some
 * of the input parameters may not be applicable (e.g. the \a iv might be
 * applicable only for encrypt and decrypt operations, and then only if the
 * key is a symmetric key and the \a blockMode requires an initialization
 * vector to be provided; similarly the \a signaturePadding parameter would
 * only be applicable for sign and verify operations; etc).
 */

/*!
 * \fn CryptoPlugin::updateCipherSessionAuthentication(quint64 clientId, const QByteArray &authenticationData, const QVariantMap &customParameters, quint32 cipherSessionToken)
 * \brief Updates the cipher session identified by the specified
 *        \a cipherSessionToken for the client identified by the given
 *        \a clientId with the specified \a authenticationData.
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Result::Failed and the error code set to
 * Sailfish::Crypto::Result::CryptoPluginIsLockedError.
 *
 * The \a customParameters will contain plugin-specific parameters which may
 * be required by the plugin.  Such parameters must be documented for clients
 * in the documentation provided with the plugin, and otherwise should be
 * ignored by plugin implementers.
 *
 * This method should only be called by clients who are attempting to use an
 * authenticated block mode (such as GCM) which require authentication data
 * to be provided before any other input data.
 */

/*!
 * \fn CryptoPlugin::updateCipherSession(quint64 clientId, const QByteArray &data, const QVariantMap &customParameters, quint32 cipherSessionToken, QByteArray *generatedData)
 * \brief Updates the cipher session identified by the specified
 *        \a cipherSessionToken for the client identified by the given
 *        \a clientId with the specified \a data, and writes any generated
 *        data (e.g. ciphertext, plaintext, or signature data) to the
 *        out-parameter \a generatedData.
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Result::Failed and the error code set to
 * Sailfish::Crypto::Result::CryptoPluginIsLockedError.
 *
 * The \a customParameters will contain plugin-specific parameters which may
 * be required by the plugin.  Such parameters must be documented for clients
 * in the documentation provided with the plugin, and otherwise should be
 * ignored by plugin implementers.
 */

/*!
 * \fn CryptoPlugin::finalizeCipherSession(quint64 clientId, const QByteArray &data, const QVariantMap &customParameters, quint32 cipherSessionToken, QByteArray *generatedData, Sailfish::Crypto::CryptoManager::VerificationStatus *verificationStatus)
 * \brief Finalizes the cipher session identified by the specified
 *        \a cipherSessionToken for the client identified by the given
 *        \a clientId, with the specified finalization \a data,
 *        and writes any generated data (e.g. ciphertext, plaintext
 *        or signature data) to the out-parameter \a generatedData,
 *        and the result of any verification to the out-parameter
 *        \a verificationStatus.
 *
 * If the plugin itself is locked, this function should return a
 * Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Result::Failed and the error code set to
 * Sailfish::Crypto::Result::CryptoPluginIsLockedError.
 *
 * The \a customParameters will contain plugin-specific parameters which may
 * be required by the plugin.  Such parameters must be documented for clients
 * in the documentation provided with the plugin, and otherwise should be
 * ignored by plugin implementers.
 *
 * In some cases, the input \a data can be ignored as it is not valid for the
 * finalization operation.
 *
 * If the cipher session operation is decryption with a symmetric algorithm
 * and the block mode is GCM, or if the cipher session operation is
 * verification of a signature, then the result of the verification should
 * be written to the \a verificationStatus out-parameter, otherwise that out-parameter
 * can be ignored.
 *
 * Note that if the cipher session operation is decryption with a symmetric
 * algorithm and the block mode is GCM and the decryption succeeded but the
 * verification failed, the plugin should still return a
 * Sailfish::Crypto::Result with the result code set to
 * Sailfish::Crypto::Result::Succeeded (as it was successfully able to
 * decrypt the input data, and determine that the input data had been
 * tampered with).  In that case, the client must check the value of the
 * \a verificationStatus out-parameter to ascertain whether or not the decrypted
 * data can be trusted.
 */
