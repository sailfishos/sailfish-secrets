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

Sailfish::Crypto::KeyData::KeyData()
    : m_origin(Sailfish::Crypto::Key::OriginUnknown)
    , m_algorithm(Sailfish::Crypto::Key::AlgorithmUnknown)
    , m_blockModes(Sailfish::Crypto::Key::BlockModeUnknown)
    , m_encryptionPaddings(Sailfish::Crypto::Key::EncryptionPaddingUnknown)
    , m_signaturePaddings(Sailfish::Crypto::Key::SignaturePaddingUnknown)
    , m_digests(Sailfish::Crypto::Key::DigestUnknown)
    , m_operations(Sailfish::Crypto::Key::OperationUnknown)
{
    m_filterData.insert(SAILFISH_SECRETS_SECRET_FILTERDATAFIELDTYPE, SAILFISH_SECRETS_SECRET_TYPECRYPTOKEY);
}

Sailfish::Crypto::KeyData::KeyData(const KeyData &other)
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

Sailfish::Crypto::KeyData &Sailfish::Crypto::KeyData::operator=(const KeyData &other)
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

bool Sailfish::Crypto::KeyData::identical(const Sailfish::Crypto::KeyData &other) const
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

bool Sailfish::Crypto::KeyData::keysEqual(const Sailfish::Crypto::KeyData &other) const
{
    return m_publicKey == other.m_publicKey
        && m_privateKey == other.m_privateKey
        && m_secretKey == other.m_secretKey;
}

bool Sailfish::Crypto::KeyData::lessThan(const Sailfish::Crypto::KeyData &other) const
{
    return m_publicKey < other.m_publicKey
        || m_privateKey < other.m_privateKey
        || m_secretKey < other.m_secretKey
        || m_algorithm < other.m_algorithm
        || m_identifier < other.m_identifier;
}


/*!
 * \class Sailfish::Crypto::Key
 * \brief An instance of a key which can be used for cryptographic operations.
 *
 * The Sailfish::Crypto::Key class encapsulates information about a
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
Sailfish::Crypto::Key::Key()
    : m_data(new Sailfish::Crypto::KeyData)
{
}

/*!
 * \brief Constructs a copy of the \a other key
 */
Sailfish::Crypto::Key::Key(const Sailfish::Crypto::Key &other)
    : m_data(new Sailfish::Crypto::KeyData)
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
Sailfish::Crypto::Key::Key(const QString &name, const QString &collection)
    : m_data(new Sailfish::Crypto::KeyData)
{
    setIdentifier(Sailfish::Crypto::Key::Identifier(name, collection));
}

/*!
 * \brief Assigns the \a other key to this key, and returns a reference to this key
 */
Sailfish::Crypto::Key& Sailfish::Crypto::Key::operator=(const Sailfish::Crypto::Key &other)
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
Sailfish::Crypto::Key::~Key()
{
    delete m_data;
}

/*!
 * \brief Returns true if the underlying data and metadata in this key are identical to those in \a other, otherwise false
 */
bool Sailfish::Crypto::Key::operator==(const Sailfish::Crypto::Key &other)
{
    return m_data->identical(*other.m_data);
}

/*!
 * \brief Returns true if this key should sort before the \a other key
 */
bool Sailfish::Crypto::Key::operator<(const Sailfish::Crypto::Key &other)
{
    return m_data->lessThan(*other.m_data);
}

/*!
 * \brief Returns the identifier of the stored key which this key references
 */
Sailfish::Crypto::Key::Identifier Sailfish::Crypto::Key::identifier() const
{
    return m_data->m_identifier;
}

/*!
 * \brief Sets the identifier of the stored key which this key references to the given \a identifier
 */
void Sailfish::Crypto::Key::setIdentifier(const Sailfish::Crypto::Key::Identifier &identifier)
{
    m_data->m_identifier = identifier;
}

/*!
 * \brief Returns information about the origin of the key
 */
Sailfish::Crypto::Key::Origin Sailfish::Crypto::Key::origin() const
{
    return m_data->m_origin;
}

/*!
 * \brief Sets origin information for the key to the given \a origin
 */
void Sailfish::Crypto::Key::setOrigin(Sailfish::Crypto::Key::Origin origin)
{
    m_data->m_origin = origin;
}

/*!
 * \brief Returns the cryptosystem algorithm this key is intended to be used with
 */
Sailfish::Crypto::Key::Algorithm Sailfish::Crypto::Key::algorithm() const
{
    return m_data->m_algorithm;
}

/*!
 * \brief Sets the cryptosystem algorithm this key is intended to be used with to \a algorithm
 */
void Sailfish::Crypto::Key::setAlgorithm(Sailfish::Crypto::Key::Algorithm algorithm)
{
    m_data->m_algorithm = algorithm;
}

/*!
 * \brief Returns the set of cipher block modes which are supported for use with this key
 */
Sailfish::Crypto::Key::BlockModes Sailfish::Crypto::Key::blockModes() const
{
    return m_data->m_blockModes;
}

/*!
 * \brief Sets the cipher block modes which are supported for use with this key to \a modes
 */
void Sailfish::Crypto::Key::setBlockModes(Sailfish::Crypto::Key::BlockModes modes)
{
    m_data->m_blockModes = modes;
}

/*!
 * \brief Returns the set of encryption padding schemes which are supported for use with this key
 */
Sailfish::Crypto::Key::EncryptionPaddings Sailfish::Crypto::Key::encryptionPaddings() const
{
    return m_data->m_encryptionPaddings;
}

/*!
 * \brief Sets the encryption padding schemes which are supported for use with this key to \a paddings
 */
void Sailfish::Crypto::Key::setEncryptionPaddings(Sailfish::Crypto::Key::EncryptionPaddings paddings)
{
    m_data->m_encryptionPaddings = paddings;
}

/*!
 * \brief Returns the set of signature padding schemes which are supported for use with this key
 */
Sailfish::Crypto::Key::SignaturePaddings Sailfish::Crypto::Key::signaturePaddings() const
{
    return m_data->m_signaturePaddings;
}

/*!
 * \brief Sets the signature padding schemes which are supported for use with this key to \a paddings
 */
void Sailfish::Crypto::Key::setSignaturePaddings(Sailfish::Crypto::Key::SignaturePaddings paddings)
{
    m_data->m_signaturePaddings = paddings;
}

/*!
 * \brief Returns the set of digests (or hash functions) which are supported for use with this key
 */
Sailfish::Crypto::Key::Digests Sailfish::Crypto::Key::digests() const
{
    return m_data->m_digests;
}

/*!
 * \brief Sets the digests (or hash functions) which are supported for use with this key to \a digests
 */
void Sailfish::Crypto::Key::setDigests(Sailfish::Crypto::Key::Digests digests)
{
    m_data->m_digests = digests;
}

/*!
 * \brief Returns the set of operations which are supported for this key
 */
Sailfish::Crypto::Key::Operations Sailfish::Crypto::Key::operations() const
{
    return m_data->m_operations;
}

/*!
 * \brief Sets the operations which are supported for this key to \a operations
 */
void Sailfish::Crypto::Key::setOperations(Sailfish::Crypto::Key::Operations operations)
{
    m_data->m_operations = operations;
}

/*!
 * \brief Returns the public key data associated with this key (asymmetric cryptosystems only)
 */
QByteArray Sailfish::Crypto::Key::publicKey() const
{
    return m_data->m_publicKey;
}

/*!
 * \brief Sets the public key data associated with this key to \a key
 */
void Sailfish::Crypto::Key::setPublicKey(const QByteArray &key)
{
    m_data->m_publicKey = key;
}

/*!
 * \brief Returns the private key data associated with this key (asymmetric cryptosystems only)
 */
QByteArray Sailfish::Crypto::Key::privateKey() const
{
    return m_data->m_privateKey;
}

/*!
 * \brief Sets the private key data associated with this key to \a key
 *
 * This field will be ignored if the algorithm specified for the key
 * is that of a symmetric cryptosystem.
 */
void Sailfish::Crypto::Key::setPrivateKey(const QByteArray &key)
{
    m_data->m_privateKey = key;
}

/*!
 * \brief Returns the private key data associated with this key (symmetric cryptosystems only)
 */
QByteArray Sailfish::Crypto::Key::secretKey() const
{
    return m_data->m_secretKey;
}

/*!
 * \breif Sets the secret key data associated with this key to \a key
 *
 * This field will be ignored if the algorithm specified for the key
 * is that of an asymmetric cryptosystem.
 */
void Sailfish::Crypto::Key::setSecretKey(const QByteArray &key)
{
    m_data->m_secretKey = key;
}

/*!
 * \brief Returns the date from which this key has become, will become, or was, valid
 */
QDateTime Sailfish::Crypto::Key::validityStart() const
{
    return m_data->m_validityStart;
}

/*!
 * \brief Sets the date from which this key has become, will become, or was, valid, to \a timestamp
 */
void Sailfish::Crypto::Key::setValidityStart(const QDateTime &timestamp)
{
    m_data->m_validityStart = timestamp;
}

/*!
 * \brief Returns the date from which this key has become or will become invalid
 */
QDateTime Sailfish::Crypto::Key::validityEnd() const
{
    return m_data->m_validityEnd;
}

/*!
 * \brief Sets the date from which this key has become or will become invalid to \a timestamp
 */
void Sailfish::Crypto::Key::setValidityEnd(const QDateTime &timestamp)
{
    m_data->m_validityEnd = timestamp;
}

/*!
 * \brief Returns the custom parameters associated with this key
 */
QVector<QByteArray> Sailfish::Crypto::Key::customParameters() const
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
void Sailfish::Crypto::Key::setCustomParameters(const QVector<QByteArray> &parameters)
{
    m_data->m_customParameters = parameters;
}

/*!
 * \brief Extracts metadata and the public key from the given \a certificate and returns a Key encapsulating that data
 */
Sailfish::Crypto::Key
Sailfish::Crypto::Key::fromCertificate(const Sailfish::Crypto::Certificate &certificate)
{
    if (certificate.type() != Sailfish::Crypto::Certificate::X509) {
        // TODO: other certificate types.
        return Sailfish::Crypto::Key();
    }

    Sailfish::Crypto::X509Certificate x509cert(Sailfish::Crypto::X509Certificate::fromCertificate(certificate));
    Sailfish::Crypto::Key retn;
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
Sailfish::Crypto::Key::FilterData
Sailfish::Crypto::Key::filterData() const
{
    return m_data->m_filterData;
}

/*!
 * \brief Returns the filter data value for the given \a field.
 */
QString
Sailfish::Crypto::Key::filterData(const QString &field) const
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
Sailfish::Crypto::Key::setFilterData(const Sailfish::Crypto::Key::FilterData &data)
{
    Sailfish::Crypto::Key::FilterData v(data);
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
Sailfish::Crypto::Key::setFilterData(const QString &field, const QString &value)
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
Sailfish::Crypto::Key::hasFilterData(const QString &field)
{
    return m_data->m_filterData.contains(field);
}
