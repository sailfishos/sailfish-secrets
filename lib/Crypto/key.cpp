/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Crypto/key.h"
#include "Crypto/key_p.h"
#include "Crypto/x509certificate.h"

#define SAILFISH_SECRETS_SECRET_FILTERDATAFIELDTYPE QLatin1String("Type")
#define SAILFISH_SECRETS_SECRET_TYPECRYPTOKEY QLatin1String("CryptoKey")

using namespace Sailfish::Crypto;

KeyData::KeyData()
    : m_origin(Key::OriginUnknown)
    , m_algorithm(Key::AlgorithmUnknown)
    , m_blockModes(Key::BlockModeUnknown)
    , m_encryptionPaddings(Key::EncryptionPaddingUnknown)
    , m_signaturePaddings(Key::SignaturePaddingUnknown)
    , m_digests(Key::DigestUnknown)
    , m_operations(Key::OperationUnknown)
{
    m_filterData.insert(SAILFISH_SECRETS_SECRET_FILTERDATAFIELDTYPE, SAILFISH_SECRETS_SECRET_TYPECRYPTOKEY);
}

KeyData::KeyData(const KeyData &other)
    : m_filterData(other.m_filterData)
    , m_customParameters(other.m_customParameters)
    , m_publicKey(other.m_publicKey)
    , m_privateKey(other.m_privateKey)
    , m_secretKey(other.m_secretKey)
    , m_validityStart(other.m_validityStart)
    , m_validityEnd(other.m_validityEnd)
    , m_identifier(other.m_identifier)
    , m_origin(other.m_origin)
    , m_algorithm(other.m_algorithm)
    , m_blockModes(other.m_blockModes)
    , m_encryptionPaddings(other.m_encryptionPaddings)
    , m_signaturePaddings(other.m_signaturePaddings)
    , m_digests(other.m_digests)
    , m_operations(other.m_operations)
{
}

KeyData &KeyData::operator=(const KeyData &other)
{
    if (this != &other) {
        m_filterData = other.m_filterData;
        m_customParameters = other.m_customParameters;
        m_publicKey = other.m_publicKey;
        m_privateKey = other.m_privateKey;
        m_secretKey = other.m_secretKey;
        m_validityStart = other.m_validityStart;
        m_validityEnd = other.m_validityEnd;
        m_identifier = other.m_identifier;
        m_origin = other.m_origin;
        m_algorithm = other.m_algorithm;
        m_blockModes = other.m_blockModes;
        m_encryptionPaddings = other.m_encryptionPaddings;
        m_signaturePaddings = other.m_signaturePaddings;
        m_digests = other.m_digests;
        m_operations = other.m_operations;
    }
    return *this;
}

bool KeyData::identical(const KeyData &other) const
{
    return m_filterData == other.m_filterData
        && m_customParameters == other.m_customParameters
        && m_publicKey == other.m_publicKey
        && m_privateKey == other.m_privateKey
        && m_secretKey == other.m_secretKey
        && m_validityStart == other.m_validityStart
        && m_validityStart == other.m_validityEnd
        && m_identifier == other.m_identifier
        && m_origin == other.m_origin
        && m_algorithm == other.m_algorithm
        && m_blockModes == other.m_blockModes
        && m_encryptionPaddings == other.m_encryptionPaddings
        && m_signaturePaddings == other.m_signaturePaddings
        && m_digests == other.m_digests
        && m_operations == other.m_operations;
}

bool KeyData::keysEqual(const KeyData &other) const
{
    return m_publicKey == other.m_publicKey
        && m_privateKey == other.m_privateKey
        && m_secretKey == other.m_secretKey;
}

bool KeyData::lessThan(const KeyData &other) const
{
    return m_publicKey < other.m_publicKey
        || m_privateKey < other.m_privateKey
        || m_secretKey < other.m_secretKey
        || m_algorithm < other.m_algorithm
        || m_identifier < other.m_identifier;
}


/*!
 * \class Key
 * \brief An instance of a key which can be used for cryptographic operations.
 *
 * The Key class encapsulates information about a
 * cryptographic key, including metadata such as the cryptosystem algorithm
 * the key is used with, the types of operations which may be performed
 * with the key, and the parameters which are supported when performing
 * operations with the key, as well as key data (private/public key data
 * for asymmetric cryptosystems, and secret key data for symmetric cryptosystems).
 *
 * In many cases, client applications need never know the key data, as the
 * key can be generated and stored securely, and then used securely by name reference,
 * without the key data ever entering the client application process address space.
 */

/*!
 * \brief Constructs an empty key
 */
Key::Key()
    : m_data(new KeyData)
{
}

/*!
 * \brief Constructs a copy of the \a other key
 */
Key::Key(const Key &other)
    : m_data(new KeyData)
{
    setFilterData(other.filterData());
    setCustomParameters(other.customParameters());
    setPublicKey(other.publicKey());
    setPrivateKey(other.privateKey());
    setSecretKey(other.secretKey());
    setValidityStart(other.validityStart());
    setValidityEnd(other.validityEnd());
    setIdentifier(other.identifier());
    setOrigin(other.origin());
    setAlgorithm(other.algorithm());
    setBlockModes(other.blockModes());
    setEncryptionPaddings(other.encryptionPaddings());
    setSignaturePaddings(other.signaturePaddings());
    setDigests(other.digests());
    setOperations(other.operations());
}

/*!
 * \brief Constructs a key which references a stored key with the given \a name from the given \a collection.
 *
 * A stored key is one which is stored securely by the Sailfish Crypto daemon,
 * whose underlying secret data (e.g. private key or secret key data) will never
 * be exposed to the client process.
 */
Key::Key(const QString &name, const QString &collection)
    : m_data(new KeyData)
{
    setIdentifier(Key::Identifier(name, collection));
}

/*!
 * \brief Assigns the \a other key to this key, and returns a reference to this key
 */
Key& Key::operator=(const Key &other)
{
    if (this != &other) {
        setFilterData(other.filterData());
        setCustomParameters(other.customParameters());
        setPublicKey(other.publicKey());
        setPrivateKey(other.privateKey());
        setSecretKey(other.secretKey());
        setValidityStart(other.validityStart());
        setValidityEnd(other.validityEnd());
        setIdentifier(other.identifier());
        setOrigin(other.origin());
        setAlgorithm(other.algorithm());
        setBlockModes(other.blockModes());
        setEncryptionPaddings(other.encryptionPaddings());
        setSignaturePaddings(other.signaturePaddings());
        setDigests(other.digests());
        setOperations(other.operations());
    }
    return *this;
}

/*!
 * \brief Destroys the key
 */
Key::~Key()
{
    delete m_data;
}

/*!
 * \brief Returns true if the underlying data and metadata in this key are identical to those in \a other, otherwise false
 */
bool Key::operator==(const Key &other)
{
    return m_data->identical(*other.m_data);
}

/*!
 * \brief Returns true if this key should sort before the \a other key
 */
bool Key::operator<(const Key &other)
{
    return m_data->lessThan(*other.m_data);
}

/*!
 * \brief Returns the identifier of the stored key which this key references
 */
Key::Identifier Key::identifier() const
{
    return m_data->m_identifier;
}

/*!
 * \brief Sets the identifier of the stored key which this key references to the given \a identifier
 */
void Key::setIdentifier(const Key::Identifier &identifier)
{
    m_data->m_identifier = identifier;
}

/*!
 * \brief Returns information about the origin of the key
 */
Key::Origin Key::origin() const
{
    return m_data->m_origin;
}

/*!
 * \brief Sets origin information for the key to the given \a origin
 */
void Key::setOrigin(Key::Origin origin)
{
    m_data->m_origin = origin;
}

/*!
 * \brief Returns the cryptosystem algorithm this key is intended to be used with
 */
Key::Algorithm Key::algorithm() const
{
    return m_data->m_algorithm;
}

/*!
 * \brief Sets the cryptosystem algorithm this key is intended to be used with to \a algorithm
 */
void Key::setAlgorithm(Key::Algorithm algorithm)
{
    m_data->m_algorithm = algorithm;
}

/*!
 * \brief Returns the set of cipher block modes which are supported for use with this key
 */
Key::BlockModes Key::blockModes() const
{
    return m_data->m_blockModes;
}

/*!
 * \brief Sets the cipher block modes which are supported for use with this key to \a modes
 */
void Key::setBlockModes(Key::BlockModes modes)
{
    m_data->m_blockModes = modes;
}

/*!
 * \brief Returns the set of encryption padding schemes which are supported for use with this key
 */
Key::EncryptionPaddings Key::encryptionPaddings() const
{
    return m_data->m_encryptionPaddings;
}

/*!
 * \brief Sets the encryption padding schemes which are supported for use with this key to \a paddings
 */
void Key::setEncryptionPaddings(Key::EncryptionPaddings paddings)
{
    m_data->m_encryptionPaddings = paddings;
}

/*!
 * \brief Returns the set of signature padding schemes which are supported for use with this key
 */
Key::SignaturePaddings Key::signaturePaddings() const
{
    return m_data->m_signaturePaddings;
}

/*!
 * \brief Sets the signature padding schemes which are supported for use with this key to \a paddings
 */
void Key::setSignaturePaddings(Key::SignaturePaddings paddings)
{
    m_data->m_signaturePaddings = paddings;
}

/*!
 * \brief Returns the set of digests (or hash functions) which are supported for use with this key
 */
Key::Digests Key::digests() const
{
    return m_data->m_digests;
}

/*!
 * \brief Sets the digests (or hash functions) which are supported for use with this key to \a digests
 */
void Key::setDigests(Key::Digests digests)
{
    m_data->m_digests = digests;
}

/*!
 * \brief Returns the set of operations which are supported for this key
 */
Key::Operations Key::operations() const
{
    return m_data->m_operations;
}

/*!
 * \brief Sets the operations which are supported for this key to \a operations
 */
void Key::setOperations(Key::Operations operations)
{
    m_data->m_operations = operations;
}

/*!
 * \brief Returns the public key data associated with this key (asymmetric cryptosystems only)
 */
QByteArray Key::publicKey() const
{
    return m_data->m_publicKey;
}

/*!
 * \brief Sets the public key data associated with this key to \a key
 */
void Key::setPublicKey(const QByteArray &key)
{
    m_data->m_publicKey = key;
}

/*!
 * \brief Returns the private key data associated with this key (asymmetric cryptosystems only)
 */
QByteArray Key::privateKey() const
{
    return m_data->m_privateKey;
}

/*!
 * \brief Sets the private key data associated with this key to \a key
 *
 * This field will be ignored if the algorithm specified for the key
 * is that of a symmetric cryptosystem.
 */
void Key::setPrivateKey(const QByteArray &key)
{
    m_data->m_privateKey = key;
}

/*!
 * \brief Returns the private key data associated with this key (symmetric cryptosystems only)
 */
QByteArray Key::secretKey() const
{
    return m_data->m_secretKey;
}

/*!
 * \breif Sets the secret key data associated with this key to \a key
 *
 * This field will be ignored if the algorithm specified for the key
 * is that of an asymmetric cryptosystem.
 */
void Key::setSecretKey(const QByteArray &key)
{
    m_data->m_secretKey = key;
}

/*!
 * \brief Returns the date from which this key has become, will become, or was, valid
 */
QDateTime Key::validityStart() const
{
    return m_data->m_validityStart;
}

/*!
 * \brief Sets the date from which this key has become, will become, or was, valid, to \a timestamp
 */
void Key::setValidityStart(const QDateTime &timestamp)
{
    m_data->m_validityStart = timestamp;
}

/*!
 * \brief Returns the date from which this key has become or will become invalid
 */
QDateTime Key::validityEnd() const
{
    return m_data->m_validityEnd;
}

/*!
 * \brief Sets the date from which this key has become or will become invalid to \a timestamp
 */
void Key::setValidityEnd(const QDateTime &timestamp)
{
    m_data->m_validityEnd = timestamp;
}

/*!
 * \brief Returns the custom parameters associated with this key
 */
QVector<QByteArray> Key::customParameters() const
{
    return m_data->m_customParameters;
}

/*!
 * \brief Sets the custom parameters associated with this key to \a parameters.
 *
 * Some cryptosystem providers (i.e. Sailfish Crypto API extension plugins)
 * may require some custom parameters to be supplied when generating, storing
 * or performing operations with keys.
 *
 * In general, these parameters will be ignored unless the extension plugin
 * requires them for some operation.
 */
void Key::setCustomParameters(const QVector<QByteArray> &parameters)
{
    m_data->m_customParameters = parameters;
}

/*!
 * \brief Extracts metadata and the public key from the given \a certificate and returns a Key encapsulating that data
 */
Key
Key::fromCertificate(const Certificate &certificate)
{
    if (certificate.type() != Certificate::X509) {
        // TODO: other certificate types.
        return Key();
    }

    X509Certificate x509cert(X509Certificate::fromCertificate(certificate));
    Key retn;
    retn.setPublicKey(x509cert.publicKey());
    // TODO: read the algorithm from the certificate
    // TODO: read the digests from the certificate
    // TODO: read the allowed operations from the X509v3 Key Usage extension:
    // retn.setOperations(x509cert.tbsCertificate().extensions.find(id-ce-keyUsage).convertToOperations(extnValue));
    // etc.

    return retn;
}

/*!
 * \brief Returns the filter data associated with this key.
 *
 * Other clients can use the filter data to find this key,
 * if they have permission to access it.  The filter data
 * is a simple map of string field to string value.
 */
Key::FilterData
Key::filterData() const
{
    return m_data->m_filterData;
}

/*!
 * \brief Returns the filter data value for the given \a field.
 */
QString
Key::filterData(const QString &field) const
{
    return m_data->m_filterData.value(field);
}

/*!
 * \brief Replaces the filter data in this key with the given \a data.
 *
 * Note that the field "Type" will always have the value "CryptoKey"
 * and this field value cannot be overwritten.
 */
void
Key::setFilterData(const Key::FilterData &data)
{
    Key::FilterData v(data);
    v.insert(SAILFISH_SECRETS_SECRET_FILTERDATAFIELDTYPE, SAILFISH_SECRETS_SECRET_TYPECRYPTOKEY);
    m_data->m_filterData = v;
}

/*!
 * \brief Sets filter data for the given \a field to the given \a value.
 *
 * Note that the field "Type" will always have the value "CryptoKey"
 * and this field value cannot be overwritten.
 */
void
Key::setFilterData(const QString &field, const QString &value)
{
    if (field.compare(SAILFISH_SECRETS_SECRET_FILTERDATAFIELDTYPE, Qt::CaseInsensitive) != 0) {
        m_data->m_filterData.insert(field, value);
    }
}

/*!
 * \brief Returns true if the key has a filter data value specified for the given \a field.
 *
 * Note that this function will always return true for the field "Type".
 */
bool
Key::hasFilterData(const QString &field)
{
    return m_data->m_filterData.contains(field);
}
