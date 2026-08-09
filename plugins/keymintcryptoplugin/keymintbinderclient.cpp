/*
 * Copyright (C) 2026 Jolla Mobile Ltd
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "keymintbinderclient_p.h"

#include <gbinder.h>

#include <QtCore/QFile>
#include <QtCore/QHash>
#include <QtCore/QMutex>
#include <QtCore/QMutexLocker>
#include <QtCore/QVector>
#include <QtCore/QtEndian>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <cstring>
#include <limits>
#include <sys/mman.h>

using namespace Sailfish::Crypto::Daemon::Plugins;

struct KeyMintEnvelope
{
    quint32 sailfishUserId;
    quint64 secureUserId;
    QByteArray identityEpoch;
    quint32 backendVersion;
    QByteArray keyBlob;
    QByteArray nonce;
    QByteArray ciphertext;
    QByteArray authenticationTag;

    KeyMintEnvelope()
        : sailfishUserId(0), secureUserId(0), backendVersion(0) {}
};

namespace {

const char KeyMintService[] =
        "android.hardware.security.keymint.IKeyMintDevice/default";
const char KeyMintInterface[] =
        "android.hardware.security.keymint.IKeyMintDevice";
const char KeyMintOperationInterface[] =
        "android.hardware.security.keymint.IKeyMintOperation";
const char BinderDevice[] = "/dev/binder";

const QByteArray EnvelopeMagic("SFSMKEY1", 8);
const QByteArray OpaqueKeyMagic("SFKMKEY1", 8);
const QByteArray MasterContextMagic("SFKMCTX1", 8);

const quint32 ProtocolVersion = 1;
const quint32 BackendVersion = 1;
const quint32 MaximumBlobSize = 1024 * 1024;
const quint32 MaximumParameters = 1024;
const quint32 MaximumCertificates = 64;
const int RootKeySize = 32;
const int IdentityEpochSize = 16;
const int GcmNonceSize = 12;
const int GcmTagSize = 16;

enum KeyMintError {
    KmOk = 0,
    KmInvalidUserId = -15,
    KmUnsupportedKeyFormat = -17,
    KmKeyUserNotAuthenticated = -26,
    KmInvalidOperationHandle = -28,
    KmTooManyOperations = -31,
    KmInvalidKeyBlob = -33,
    KmInvalidArgument = -38,
    KmUnsupportedTag = -39,
    KmConcurrentAccessConflict = -47,
    KmSecureHardwareCommunicationFailed = -49,
    KmAttestationChallengeMissing = -63,
    KmNotConfigured = -64,
    KmHardwareTypeUnavailable = -68,
    KmUnimplemented = -100,
    KmUnknownError = -1000
};

enum DeviceTransaction {
    GetHardwareInfoTransaction = 1,
    AddRngEntropyTransaction = 2,
    GenerateKeyTransaction = 3,
    ImportKeyTransaction = 4,
    ImportWrappedKeyTransaction = 5,
    UpgradeKeyTransaction = 6,
    DeleteKeyTransaction = 7,
    DeleteAllKeysTransaction = 8,
    DestroyAttestationIdsTransaction = 9,
    BeginTransaction = 10,
    DeviceLockedTransaction = 11,
    EarlyBootEndedTransaction = 12,
    ConvertStorageKeyTransaction = 13,
    GetKeyCharacteristicsTransaction = 14
};

enum OperationTransaction {
    UpdateAadTransaction = 1,
    UpdateTransaction = 2,
    FinishTransaction = 3,
    AbortTransaction = 4
};

enum AppSupportOperation {
    CapabilitiesOperation = 1,
    GenerateOperation = 2,
    ImportOperation = 3,
    ExportOperation = 4,
    CharacteristicsOperation = 5,
    DeleteOperation = 6,
    DeleteAllOperation = 7,
    BeginOperation = 8,
    UpdateOperation = 9,
    FinishOperation = 10,
    AbortOperation = 11,
    AddEntropyOperation = 12,
    UpgradeOperation = 13,
    AttestOperation = 14,
    ImportWrappedOperation = 15
};

enum KeyPurpose {
    PurposeEncrypt = 0,
    PurposeDecrypt = 1
};

enum KeyParameterValueTag {
    ValueInvalid = 0,
    ValueAlgorithm = 1,
    ValueBlockMode = 2,
    ValuePaddingMode = 3,
    ValueDigest = 4,
    ValueEcCurve = 5,
    ValueOrigin = 6,
    ValueKeyPurpose = 7,
    ValueHardwareAuthenticatorType = 8,
    ValueSecurityLevel = 9,
    ValueBool = 10,
    ValueInteger = 11,
    ValueLongInteger = 12,
    ValueDateTime = 13,
    ValueBlob = 14
};

const quint32 TagPurpose = 0x20000001U;
const quint32 TagAlgorithm = 0x10000002U;
const quint32 TagKeySize = 0x30000003U;
const quint32 TagBlockMode = 0x20000004U;
const quint32 TagDigest = 0x20000005U;
const quint32 TagPadding = 0x20000006U;
const quint32 TagMinMacLength = 0x30000008U;
const quint32 TagEcCurve = 0x1000000aU;
const quint32 TagHardwareType = 0x10000130U;
const quint32 TagUserSecureId = 0xa00001f6U;
const quint32 TagNoAuthRequired = 0x700001f7U;
const quint32 TagUserAuthType = 0x100001f8U;
const quint32 TagAuthTimeout = 0x300001f9U;
const quint32 TagOrigin = 0x100002beU;
const quint32 TagAssociatedData = 0x900003e8U;
const quint32 TagNonce = 0x900003e9U;
const quint32 TagMacLength = 0x300003ebU;
const quint32 TagConfirmationToken = 0x900003edU;

const qint32 AlgorithmAes = 32;
const qint32 BlockModeGcm = 32;
const qint32 PaddingNone = 1;
const qint32 AuthenticatorPassword = 1;
const qint32 AuthenticatorFingerprint = 2;

enum BinderException {
    ExceptionNone = 0,
    ExceptionServiceSpecific = -8,
    ExceptionHasReplyHeader = -128
};

// android.hardware.security.keymint.SecurityLevel.  KEYSTORE (100) is not a
// KeyMint hardware implementation and must never be advertised to AppSupport
// as one.
enum KeyMintSecurityLevel {
    SecurityLevelSoftware = 0,
    SecurityLevelTrustedEnvironment = 1,
    SecurityLevelStrongBox = 2
};

template<typename T>
void appendLittleEndian(QByteArray *output, T value)
{
    const T encoded = qToLittleEndian(value);
    output->append(reinterpret_cast<const char *>(&encoded), sizeof(encoded));
}

void appendBlob(QByteArray *output, const QByteArray &blob)
{
    appendLittleEndian(output, quint32(blob.size()));
    output->append(blob);
}

QByteArray serializeCapabilitiesResponse(qint32 securityLevel)
{
    // AKS Capabilities response v1 is exactly two little-endian u32 values:
    // protocol version at offset 0 and KeyMint SecurityLevel at offset 4.
    if (securityLevel != SecurityLevelSoftware
            && securityLevel != SecurityLevelTrustedEnvironment
            && securityLevel != SecurityLevelStrongBox) {
        return QByteArray();
    }
    QByteArray response;
    appendLittleEndian(&response, ProtocolVersion);
    appendLittleEndian(&response, quint32(securityLevel));
    return response;
}

class Cursor
{
public:
    explicit Cursor(const QByteArray &data)
        : m_data(data), m_offset(0) {}

    template<typename T>
    bool take(T *value)
    {
        if (!value || remaining() < static_cast<int>(sizeof(T))) {
            return false;
        }
        *value = qFromLittleEndian<T>(
                    reinterpret_cast<const uchar *>(m_data.constData() + m_offset));
        m_offset += sizeof(T);
        return true;
    }

    bool takeBlob(QByteArray *blob, quint32 maximumSize = MaximumBlobSize)
    {
        quint32 size = 0;
        if (!blob || !take(&size) || size > maximumSize
                || remaining() < static_cast<int>(size)) {
            return false;
        }
        *blob = m_data.mid(m_offset, static_cast<int>(size));
        m_offset += size;
        return true;
    }

    bool takeBytes(int size, QByteArray *bytes)
    {
        if (!bytes || size < 0 || remaining() < size) {
            return false;
        }
        *bytes = m_data.mid(m_offset, size);
        m_offset += size;
        return true;
    }

    int remaining() const { return m_data.size() - m_offset; }
    bool atEnd() const { return m_offset == m_data.size(); }

private:
    const QByteArray m_data;
    int m_offset;
};

struct Parameter
{
    quint32 tag;
    qint32 valueTag;
    quint64 scalar;
    QByteArray blob;

    Parameter()
        : tag(0), valueTag(ValueInvalid), scalar(0) {}
};

struct HardwareAuthToken
{
    bool present;
    quint32 version;
    quint64 challenge;
    quint64 userId;
    quint64 authenticatorId;
    quint32 authenticatorType;
    quint64 timestamp;
    QByteArray mac;

    HardwareAuthToken()
        : present(false), version(0), challenge(0), userId(0),
          authenticatorId(0), authenticatorType(0), timestamp(0) {}
};

struct OpaqueKey
{
    QByteArray rawBlob;
    QVector<QByteArray> certificates;
    QByteArray publicKey;
};

struct Characteristics
{
    QVector<Parameter> hardware;
    QVector<Parameter> software;
};

struct KeyCreation
{
    OpaqueKey key;
    Characteristics characteristics;
};

quint32 canonicalType(quint32 tag)
{
    switch (tag & 0xf0000000U) {
    case 0x70000000U:
        return 1;
    case 0x10000000U:
    case 0x20000000U:
    case 0x30000000U:
    case 0x40000000U:
        return 2;
    case 0x50000000U:
    case 0x60000000U:
    case 0xa0000000U:
        return 3;
    case 0x80000000U:
    case 0x90000000U:
        return 4;
    default:
        return 0;
    }
}

qint32 parameterValueTag(quint32 tag)
{
    switch (tag) {
    case TagAlgorithm:
        return ValueAlgorithm;
    case TagBlockMode:
        return ValueBlockMode;
    case TagPadding:
        return ValuePaddingMode;
    case TagDigest:
        return ValueDigest;
    case TagEcCurve:
        return ValueEcCurve;
    case TagOrigin:
        return ValueOrigin;
    case TagPurpose:
        return ValueKeyPurpose;
    case TagUserAuthType:
        return ValueHardwareAuthenticatorType;
    case TagHardwareType:
        return ValueSecurityLevel;
    default:
        break;
    }
    switch (canonicalType(tag)) {
    case 1:
        return ValueBool;
    case 2:
        return ValueInteger;
    case 3:
        return (tag & 0xf0000000U) == 0x60000000U
                ? ValueDateTime : ValueLongInteger;
    case 4:
        return ValueBlob;
    default:
        return ValueInvalid;
    }
}

Parameter scalarParameter(quint32 tag, quint64 value)
{
    Parameter parameter;
    parameter.tag = tag;
    parameter.valueTag = parameterValueTag(tag);
    parameter.scalar = value;
    return parameter;
}

Parameter blobParameter(quint32 tag, const QByteArray &value)
{
    Parameter parameter;
    parameter.tag = tag;
    parameter.valueTag = ValueBlob;
    parameter.blob = value;
    return parameter;
}

bool parseAuthSet(const QByteArray &serialized, QVector<Parameter> *parameters)
{
    Cursor cursor(serialized);
    quint32 version = 0;
    quint32 count = 0;
    if (!parameters || !cursor.take(&version) || version != ProtocolVersion
            || !cursor.take(&count) || count > MaximumParameters) {
        return false;
    }
    QVector<Parameter> parsed;
    parsed.reserve(static_cast<int>(count));
    for (quint32 i = 0; i < count; ++i) {
        Parameter parameter;
        quint32 type = 0;
        if (!cursor.take(&parameter.tag) || parameter.tag == 0
                || !cursor.take(&type) || type != canonicalType(parameter.tag)
                || !cursor.take(&parameter.scalar)
                || !cursor.takeBlob(&parameter.blob)) {
            return false;
        }
        if ((type == 1 && (parameter.scalar > 1 || !parameter.blob.isEmpty()))
                || ((type == 2 || type == 3) && !parameter.blob.isEmpty())
                || (type == 2 && parameter.scalar > 0xffffffffULL)
                || (type == 4 && parameter.scalar != 0)) {
            return false;
        }
        parameter.valueTag = parameterValueTag(parameter.tag);
        if (parameter.valueTag == ValueInvalid) {
            return false;
        }
        parsed.append(parameter);
    }
    if (!cursor.atEnd()) {
        return false;
    }
    *parameters = parsed;
    return true;
}

QByteArray serializeAuthSet(const QVector<Parameter> &parameters)
{
    if (parameters.size() > static_cast<int>(MaximumParameters)) {
        return QByteArray();
    }
    QByteArray serialized;
    appendLittleEndian(&serialized, ProtocolVersion);
    appendLittleEndian(&serialized, quint32(parameters.size()));
    for (const Parameter &parameter : parameters) {
        const quint32 type = canonicalType(parameter.tag);
        if (!type) {
            return QByteArray();
        }
        appendLittleEndian(&serialized, parameter.tag);
        appendLittleEndian(&serialized, type);
        appendLittleEndian(&serialized, parameter.scalar);
        appendBlob(&serialized, parameter.blob);
    }
    return serialized;
}

QByteArray serializeCharacteristics(const Characteristics &characteristics)
{
    const QByteArray hardware = serializeAuthSet(characteristics.hardware);
    const QByteArray software = serializeAuthSet(characteristics.software);
    if (hardware.isEmpty() || software.isEmpty()) {
        return QByteArray();
    }
    QByteArray serialized;
    appendLittleEndian(&serialized, ProtocolVersion);
    appendBlob(&serialized, hardware);
    appendBlob(&serialized, software);
    return serialized;
}

bool policyMatchesIdentity(const QVector<Parameter> &parameters,
                           quint64 activeSecureUserId,
                           quint64 activeFingerprintAuthenticatorId)
{
    bool noAuthenticationRequired = false;
    bool fingerprintAuthenticationAllowed = false;
    bool haveSecureUserId = false;
    bool secureUserIdsValid = true;
    for (const Parameter &parameter : parameters) {
        if (parameter.tag == TagNoAuthRequired
                && parameter.valueTag == ValueBool && parameter.scalar == 1) {
            noAuthenticationRequired = true;
        } else if (parameter.tag == TagUserAuthType
                   && parameter.valueTag == ValueHardwareAuthenticatorType
                   && (parameter.scalar & AuthenticatorFingerprint) != 0) {
            fingerprintAuthenticationAllowed = true;
        }
    }
    for (const Parameter &parameter : parameters) {
        if (parameter.tag == TagUserSecureId
                && parameter.valueTag == ValueLongInteger) {
            haveSecureUserId = true;
            if (parameter.scalar != activeSecureUserId
                    && (!fingerprintAuthenticationAllowed
                        || !activeFingerprintAuthenticatorId
                        || parameter.scalar != activeFingerprintAuthenticatorId)) {
                secureUserIdsValid = false;
            }
        }
    }
    return noAuthenticationRequired
            ? !haveSecureUserId : haveSecureUserId && secureUserIdsValid;
}

bool tokenMatchesIdentity(const HardwareAuthToken &token,
                          quint64 activeSecureUserId,
                          quint64 activeFingerprintAuthenticatorId)
{
    if (token.userId != activeSecureUserId) {
        return false;
    }
    if (token.authenticatorType == AuthenticatorPassword) {
        return token.authenticatorId == 0;
    }
    if (token.authenticatorType == AuthenticatorFingerprint) {
        return activeFingerprintAuthenticatorId
                && token.authenticatorId == activeFingerprintAuthenticatorId;
    }
    return false;
}

bool readRandom(QByteArray *output, int size)
{
    QFile random(QStringLiteral("/dev/urandom"));
    if (!output || size <= 0 || !random.open(QIODevice::ReadOnly)) {
        return false;
    }
    *output = random.read(size);
    return output->size() == size;
}

void clearSecret(QByteArray *secret)
{
    if (secret && !secret->isEmpty()) {
        OPENSSL_cleanse(secret->data(), secret->size());
        secret->clear();
    }
}

QByteArray extractPublicKey(const QVector<QByteArray> &certificates)
{
    if (certificates.isEmpty() || certificates.first().isEmpty()) {
        return QByteArray();
    }
    const QByteArray &encoded = certificates.first();
    const unsigned char *position =
            reinterpret_cast<const unsigned char *>(encoded.constData());
    X509 *certificate = d2i_X509(Q_NULLPTR, &position, encoded.size());
    if (!certificate) {
        position = reinterpret_cast<const unsigned char *>(encoded.constData());
        EVP_PKEY *direct = d2i_PUBKEY(Q_NULLPTR, &position, encoded.size());
        if (!direct) {
            return QByteArray();
        }
        const int size = i2d_PUBKEY(direct, Q_NULLPTR);
        QByteArray result;
        if (size > 0) {
            result.resize(size);
            unsigned char *output = reinterpret_cast<unsigned char *>(result.data());
            if (i2d_PUBKEY(direct, &output) != size) {
                result.clear();
            }
        }
        EVP_PKEY_free(direct);
        return result;
    }
    EVP_PKEY *publicKey = X509_get_pubkey(certificate);
    QByteArray result;
    if (publicKey) {
        const int size = i2d_PUBKEY(publicKey, Q_NULLPTR);
        if (size > 0) {
            result.resize(size);
            unsigned char *output = reinterpret_cast<unsigned char *>(result.data());
            if (i2d_PUBKEY(publicKey, &output) != size) {
                result.clear();
            }
        }
        EVP_PKEY_free(publicKey);
    }
    X509_free(certificate);
    return result;
}

QByteArray serializeOpaqueKey(const OpaqueKey &key)
{
    if (key.rawBlob.isEmpty() || key.rawBlob.size() > static_cast<int>(MaximumBlobSize)
            || key.certificates.size() > static_cast<int>(MaximumCertificates)) {
        return QByteArray();
    }
    QByteArray serialized(OpaqueKeyMagic);
    appendLittleEndian(&serialized, ProtocolVersion);
    appendBlob(&serialized, key.rawBlob);
    appendLittleEndian(&serialized, quint32(key.certificates.size()));
    for (const QByteArray &certificate : key.certificates) {
        appendBlob(&serialized, certificate);
    }
    appendBlob(&serialized, key.publicKey);
    return serialized.size() <= static_cast<int>(MaximumBlobSize)
            ? serialized : QByteArray();
}

bool parseOpaqueKey(const QByteArray &serialized, OpaqueKey *key)
{
    if (!key || serialized.isEmpty() || serialized.size() > static_cast<int>(MaximumBlobSize)) {
        return false;
    }
    if (!serialized.startsWith(OpaqueKeyMagic)) {
        key->rawBlob = serialized;
        key->certificates.clear();
        key->publicKey.clear();
        return true;
    }
    Cursor cursor(serialized.mid(OpaqueKeyMagic.size()));
    quint32 version = 0;
    quint32 count = 0;
    OpaqueKey parsed;
    if (!cursor.take(&version) || version != ProtocolVersion
            || !cursor.takeBlob(&parsed.rawBlob) || parsed.rawBlob.isEmpty()
            || !cursor.take(&count) || count > MaximumCertificates) {
        return false;
    }
    for (quint32 i = 0; i < count; ++i) {
        QByteArray certificate;
        if (!cursor.takeBlob(&certificate) || certificate.isEmpty()) {
            return false;
        }
        parsed.certificates.append(certificate);
    }
    if (!cursor.takeBlob(&parsed.publicKey) || !cursor.atEnd()) {
        return false;
    }
    *key = parsed;
    return true;
}

QByteArray authenticatedEnvelopeData(const KeyMintEnvelope &envelope)
{
    QByteArray serialized(EnvelopeMagic);
    appendLittleEndian(&serialized, quint16(1));
    appendLittleEndian(&serialized, quint16(0));
    appendLittleEndian(&serialized, envelope.sailfishUserId);
    appendLittleEndian(&serialized, envelope.secureUserId);
    appendLittleEndian(&serialized, envelope.backendVersion);
    appendBlob(&serialized, envelope.identityEpoch);
    appendBlob(&serialized, envelope.keyBlob);
    appendBlob(&serialized, envelope.nonce);
    return serialized;
}

QByteArray serializeEnvelope(const KeyMintEnvelope &envelope)
{
    if (!envelope.sailfishUserId || !envelope.secureUserId
            || envelope.identityEpoch.size() != IdentityEpochSize
            || !envelope.backendVersion || envelope.keyBlob.isEmpty()
            || envelope.nonce.isEmpty() || envelope.nonce.size() > 32
            || envelope.ciphertext.size() != RootKeySize
            || envelope.authenticationTag.isEmpty()
            || envelope.authenticationTag.size() > 32) {
        return QByteArray();
    }
    QByteArray serialized = authenticatedEnvelopeData(envelope);
    appendBlob(&serialized, envelope.ciphertext);
    appendBlob(&serialized, envelope.authenticationTag);
    return serialized.size() <= static_cast<int>(MaximumBlobSize)
            ? serialized : QByteArray();
}

bool parseEnvelope(const QByteArray &serialized, KeyMintEnvelope *envelope)
{
    if (!envelope || !serialized.startsWith(EnvelopeMagic)
            || serialized.size() > static_cast<int>(MaximumBlobSize)) {
        return false;
    }
    Cursor cursor(serialized.mid(EnvelopeMagic.size()));
    quint16 version = 0;
    quint16 reserved = 0;
    KeyMintEnvelope parsed;
    if (!cursor.take(&version) || version != 1
            || !cursor.take(&reserved) || reserved != 0
            || !cursor.take(&parsed.sailfishUserId) || !parsed.sailfishUserId
            || !cursor.take(&parsed.secureUserId) || !parsed.secureUserId
            || !cursor.take(&parsed.backendVersion) || !parsed.backendVersion
            || !cursor.takeBlob(&parsed.identityEpoch, IdentityEpochSize)
            || parsed.identityEpoch.size() != IdentityEpochSize
            || !cursor.takeBlob(&parsed.keyBlob) || parsed.keyBlob.isEmpty()
            || !cursor.takeBlob(&parsed.nonce, 32) || parsed.nonce.isEmpty()
            || !cursor.takeBlob(&parsed.ciphertext, RootKeySize)
            || parsed.ciphertext.size() != RootKeySize
            || !cursor.takeBlob(&parsed.authenticationTag, 32)
            || parsed.authenticationTag.isEmpty() || !cursor.atEnd()) {
        return false;
    }
    *envelope = parsed;
    return true;
}

void appendByteArray(GBinderWriter *writer, const QByteArray &bytes)
{
    if (bytes.isEmpty()) {
        gbinder_writer_append_int32(writer, 0);
    } else {
        gbinder_writer_append_byte_array(
                    writer,
                    reinterpret_cast<const guint8 *>(bytes.constData()),
                    bytes.size());
    }
}

void appendNullByteArray(GBinderWriter *writer)
{
    gbinder_writer_append_int32(writer, static_cast<guint32>(-1));
}

bool readByteArray(GBinderReader *reader, QByteArray *bytes,
                   quint32 maximumSize = MaximumBlobSize)
{
    const gsize before = gbinder_reader_bytes_read(reader);
    gsize size = 0;
    const guint8 *data = static_cast<const guint8 *>(
                gbinder_reader_read_byte_array(reader, &size));
    if (gbinder_reader_bytes_read(reader) == before || size > maximumSize
            || (size && !data)) {
        return false;
    }
    if (bytes) {
        *bytes = size ? QByteArray(reinterpret_cast<const char *>(data), size)
                      : QByteArray();
    }
    return true;
}

bool startParcelable(GBinderReader *reader, gsize *end, bool *nonNull)
{
    guint32 present = 0;
    if (!reader || !end || !nonNull
            || !gbinder_reader_read_uint32(reader, &present) || present > 1) {
        return false;
    }
    *nonNull = present != 0;
    if (!*nonNull) {
        *end = gbinder_reader_bytes_read(reader);
        return true;
    }
    guint32 size = 0;
    if (!gbinder_reader_read_uint32(reader, &size) || size < sizeof(size)
            || size - sizeof(size) > gbinder_reader_bytes_remaining(reader)) {
        return false;
    }
    *end = gbinder_reader_bytes_read(reader) + size - sizeof(size);
    return true;
}

bool finishParcelable(GBinderReader *reader, gsize end)
{
    return reader && gbinder_reader_bytes_read(reader) == end;
}

void writeParameter(GBinderWriter *writer, const Parameter &parameter)
{
    GBinderWriter parameterWriter;
    gbinder_writer_start_parcelable(writer, &parameterWriter);
    gbinder_writer_append_int32(&parameterWriter, parameter.tag);

    // KeyParameterValue is an AIDL union.  writeParcelable() prefixes it with
    // the non-null marker, but unlike a structured parcelable the union itself
    // has no size field.
    gbinder_writer_append_int32(&parameterWriter, 1);
    gbinder_writer_append_int32(&parameterWriter, parameter.valueTag);
    switch (parameter.valueTag) {
    case ValueLongInteger:
    case ValueDateTime:
        gbinder_writer_append_int64(&parameterWriter, parameter.scalar);
        break;
    case ValueBlob:
        appendByteArray(&parameterWriter, parameter.blob);
        break;
    default:
        gbinder_writer_append_int32(&parameterWriter, quint32(parameter.scalar));
        break;
    }
    gbinder_writer_finish_parcelable(&parameterWriter);
}

void writeParameters(GBinderWriter *writer, const QVector<Parameter> &parameters)
{
    gbinder_writer_append_int32(writer, parameters.size());
    for (const Parameter &parameter : parameters) {
        writeParameter(writer, parameter);
    }
}

bool readParameter(GBinderReader *reader, Parameter *parameter)
{
    gsize parameterEnd = 0;
    bool nonNull = false;
    if (!parameter || !startParcelable(reader, &parameterEnd, &nonNull)
            || !nonNull) {
        return false;
    }
    guint32 rawTag = 0;
    bool ok = gbinder_reader_read_uint32(reader, &rawTag) && rawTag;
    guint32 valuePresent = 0;
    ok = ok && gbinder_reader_read_uint32(reader, &valuePresent)
            && valuePresent == 1;
    gint32 valueTag = ValueInvalid;
    ok = ok && gbinder_reader_read_int32(reader, &valueTag);
    quint64 scalar = 0;
    QByteArray blob;
    if (ok) {
        switch (valueTag) {
        case ValueLongInteger:
        case ValueDateTime: {
            guint64 value = 0;
            ok = gbinder_reader_read_uint64(reader, &value);
            scalar = value;
            break;
        }
        case ValueBlob:
            ok = readByteArray(reader, &blob);
            break;
        case ValueInvalid:
        case ValueAlgorithm:
        case ValueBlockMode:
        case ValuePaddingMode:
        case ValueDigest:
        case ValueEcCurve:
        case ValueOrigin:
        case ValueKeyPurpose:
        case ValueHardwareAuthenticatorType:
        case ValueSecurityLevel:
        case ValueBool:
        case ValueInteger: {
            guint32 value = 0;
            ok = gbinder_reader_read_uint32(reader, &value);
            scalar = value;
            break;
        }
        default:
            ok = false;
            break;
        }
    }
    if (!ok || !finishParcelable(reader, parameterEnd)
            || parameterValueTag(rawTag) != valueTag) {
        return false;
    }
    parameter->tag = rawTag;
    parameter->valueTag = valueTag;
    parameter->scalar = scalar;
    parameter->blob = blob;
    return true;
}

bool readParameters(GBinderReader *reader, QVector<Parameter> *parameters)
{
    gint32 count = 0;
    if (!parameters || !gbinder_reader_read_int32(reader, &count)
            || count < 0 || count > static_cast<gint32>(MaximumParameters)) {
        return false;
    }
    QVector<Parameter> parsed;
    parsed.reserve(count);
    for (gint32 i = 0; i < count; ++i) {
        Parameter parameter;
        if (!readParameter(reader, &parameter)) {
            return false;
        }
        parsed.append(parameter);
    }
    *parameters = parsed;
    return true;
}

void writeHardwareAuthToken(GBinderWriter *writer,
                            const HardwareAuthToken &token)
{
    if (!token.present) {
        gbinder_writer_append_null_parcelable(writer);
        return;
    }
    GBinderWriter tokenWriter;
    gbinder_writer_start_parcelable(writer, &tokenWriter);
    gbinder_writer_append_int64(&tokenWriter, token.challenge);
    gbinder_writer_append_int64(&tokenWriter, token.userId);
    gbinder_writer_append_int64(&tokenWriter, token.authenticatorId);
    gbinder_writer_append_int32(&tokenWriter, token.authenticatorType);

    GBinderWriter timestampWriter;
    gbinder_writer_start_parcelable(&tokenWriter, &timestampWriter);
    gbinder_writer_append_int64(&timestampWriter, token.timestamp);
    gbinder_writer_finish_parcelable(&timestampWriter);
    appendByteArray(&tokenWriter, token.mac);
    gbinder_writer_finish_parcelable(&tokenWriter);
}

bool parseMasterHardwareAuthToken(const QByteArray &serialized,
                                  HardwareAuthToken *token)
{
    Cursor cursor(serialized);
    HardwareAuthToken parsed;
    if (!cursor.take(&parsed.version) || parsed.version > 1
            || !cursor.take(&parsed.challenge)
            || !cursor.take(&parsed.userId)
            || !cursor.take(&parsed.authenticatorId)
            || !cursor.take(&parsed.authenticatorType)
            || !cursor.take(&parsed.timestamp) || !parsed.timestamp
            || !cursor.takeBytes(32, &parsed.mac) || !cursor.atEnd()) {
        return false;
    }
    parsed.present = true;
    *token = parsed;
    return true;
}

bool parseAppHardwareAuthToken(Cursor *cursor, HardwareAuthToken *token)
{
    quint32 present = 0;
    HardwareAuthToken parsed;
    if (!cursor || !token || !cursor->take(&present) || present > 1) {
        return false;
    }
    if (!present) {
        *token = parsed;
        return true;
    }
    if (!cursor->take(&parsed.version) || parsed.version != 1
            || !cursor->take(&parsed.challenge)
            || !cursor->take(&parsed.userId)
            || !cursor->take(&parsed.authenticatorId)
            || !cursor->take(&parsed.authenticatorType)
            || !cursor->take(&parsed.timestamp)
            || !cursor->takeBlob(&parsed.mac, 32) || parsed.mac.size() != 32) {
        return false;
    }
    parsed.present = true;
    *token = parsed;
    return true;
}

bool emptyVerificationToken(const QByteArray &serialized)
{
    if (serialized.isEmpty()) {
        return true;
    }
    Cursor cursor(serialized);
    quint32 version = 0;
    quint64 challenge = 0;
    quint64 timestamp = 0;
    quint32 securityLevel = 0;
    QByteArray parametersData;
    QByteArray mac;
    QVector<Parameter> parameters;
    if (!cursor.take(&version) || version != 1
            || !cursor.take(&challenge) || !cursor.take(&timestamp)
            || !cursor.take(&securityLevel)
            || !cursor.takeBlob(&parametersData)
            || !parseAuthSet(parametersData, &parameters)
            || !cursor.takeBlob(&mac, 32) || !cursor.atEnd()) {
        return false;
    }
    bool macIsEmpty = true;
    for (char value : mac) {
        if (value != 0) {
            macIsEmpty = false;
            break;
        }
    }
    return challenge == 0 && timestamp == 0 && securityLevel == 0
            && parameters.isEmpty()
            && (mac.isEmpty() || macIsEmpty);
}

QVector<QByteArray> associatedData(const QVector<Parameter> &parameters)
{
    QVector<QByteArray> result;
    for (const Parameter &parameter : parameters) {
        if (parameter.tag == TagAssociatedData && parameter.valueTag == ValueBlob) {
            result.append(parameter.blob);
        }
    }
    return result;
}

QByteArray confirmationToken(const QVector<Parameter> &parameters)
{
    for (const Parameter &parameter : parameters) {
        if (parameter.tag == TagConfirmationToken && parameter.valueTag == ValueBlob) {
            return parameter.blob;
        }
    }
    return QByteArray();
}

QByteArray nonceFromParameters(const QVector<Parameter> &parameters)
{
    for (const Parameter &parameter : parameters) {
        if (parameter.tag == TagNonce && parameter.valueTag == ValueBlob) {
            return parameter.blob;
        }
    }
    return QByteArray();
}

} // namespace

KeyMintBinderClient::CallResult::CallResult(
        bool succeeded,
        qint32 error,
        const QString &message)
    : transportSucceeded(succeeded)
    , keyMintError(error)
    , errorMessage(message)
{
}

bool KeyMintBinderClient::CallResult::succeeded() const
{
    return transportSucceeded && keyMintError == KmOk;
}

class KeyMintBinderClient::Private
{
public:
    struct BinderOperation {
        GBinderRemoteObject *remote;
        GBinderClient *client;
        quint64 challenge;

        BinderOperation()
            : remote(Q_NULLPTR), client(Q_NULLPTR), challenge(0) {}
    };

    struct MasterOperation {
        QByteArray context;
        QByteArray rootKey;
        KeyMintEnvelope envelope;
        BinderOperation *operation;
        bool create;

        MasterOperation()
            : operation(Q_NULLPTR), create(false) {}
    };

    Private()
        : serviceManager(Q_NULLPTR)
        , remote(Q_NULLPTR)
        , client(Q_NULLPTR)
        , activeSecureUserId(0)
        , brokerSecureUserId(0)
        , activeFingerprintAuthenticatorId(0)
        , nextOperationHandle(0x8000000000000001ULL)
    {
    }

    ~Private()
    {
        QMutexLocker locker(&mutex);
        clearOperations();
        clearService();
        if (serviceManager) {
            gbinder_servicemanager_unref(serviceManager);
        }
    }

    CallResult ensureClient()
    {
        if (client && remote && !gbinder_remote_object_is_dead(remote)) {
            return CallResult(true, KmOk);
        }
        clearOperations();
        clearService();
        if (!serviceManager) {
            serviceManager = gbinder_servicemanager_new(BinderDevice);
        }
        if (!serviceManager) {
            return CallResult(false, KmHardwareTypeUnavailable,
                              QStringLiteral("Unable to open /dev/binder"));
        }
        GBinderRemoteObject *service = gbinder_servicemanager_get_service_sync(
                    serviceManager, KeyMintService, Q_NULLPTR);
        if (!service) {
            return CallResult(false, KmHardwareTypeUnavailable,
                              QStringLiteral("AIDL KeyMint service is unavailable"));
        }
        // The synchronous service-manager lookup returns an autoreleased
        // object.  Keep an independent reference for the lifetime of the
        // client so clearService() cannot release the manager's reference.
        remote = gbinder_remote_object_ref(service);
        client = gbinder_client_new(remote, KeyMintInterface);
        if (!client) {
            clearService();
            return CallResult(false, KmHardwareTypeUnavailable,
                              QStringLiteral("Unable to create AIDL KeyMint client"));
        }
        return CallResult(true, KmOk);
    }

    void clearService()
    {
        if (client) {
            gbinder_client_unref(client);
            client = Q_NULLPTR;
        }
        if (remote) {
            gbinder_remote_object_unref(remote);
            remote = Q_NULLPTR;
        }
    }

    static void destroyOperation(BinderOperation *operation, bool sendAbort)
    {
        if (!operation) {
            return;
        }
        if (sendAbort && operation->client) {
            GBinderLocalRequest *request = gbinder_client_new_request(operation->client);
            if (request) {
                int status = 0;
                GBinderRemoteReply *reply = gbinder_client_transact_sync_reply(
                            operation->client, AbortTransaction, request, &status);
                if (reply) {
                    gbinder_remote_reply_unref(reply);
                }
                gbinder_local_request_unref(request);
            }
        }
        if (operation->client) {
            gbinder_client_unref(operation->client);
        }
        if (operation->remote) {
            gbinder_remote_object_unref(operation->remote);
        }
        delete operation;
    }

    static void destroyMasterOperation(MasterOperation *operation, bool sendAbort)
    {
        if (!operation) {
            return;
        }
        destroyOperation(operation->operation, sendAbort);
        if (!operation->rootKey.isEmpty()) {
            OPENSSL_cleanse(operation->rootKey.data(), operation->rootKey.size());
            ::munlock(operation->rootKey.data(), operation->rootKey.size());
            operation->rootKey.clear();
        }
        delete operation;
    }

    void clearAppOperations(bool sendAbort)
    {
        for (BinderOperation *operation : appOperations) {
            destroyOperation(operation, sendAbort);
        }
        appOperations.clear();
    }

    void clearOperations()
    {
        clearAppOperations(false);
        for (MasterOperation *operation : masterOperations) {
            destroyMasterOperation(operation, false);
        }
        masterOperations.clear();
        masterChallenges.clear();
    }

    CallResult transact(GBinderClient *target,
                        quint32 transaction,
                        GBinderLocalRequest *request,
                        GBinderRemoteReply **reply,
                        GBinderReader *reader)
    {
        if (!target || !request || !reply || !reader) {
            return CallResult(false, KmInvalidArgument,
                              QStringLiteral("Invalid Binder transaction"));
        }
        *reply = Q_NULLPTR;
        int binderStatus = 0;
        *reply = gbinder_client_transact_sync_reply(
                    target, transaction, request, &binderStatus);
        if (!*reply) {
            return CallResult(false, KmSecureHardwareCommunicationFailed,
                              QStringLiteral("AIDL KeyMint Binder transaction failed (%1)")
                              .arg(binderStatus));
        }
        gbinder_remote_reply_init_reader(*reply, reader);
        gint32 exception = ExceptionNone;
        if (!gbinder_reader_read_int32(reader, &exception)) {
            return CallResult(false, KmSecureHardwareCommunicationFailed,
                              QStringLiteral("AIDL KeyMint reply has no status"));
        }
        if (exception == ExceptionHasReplyHeader) {
            gint32 size = 0;
            if (!gbinder_reader_read_int32(reader, &size) || size < 4
                    || (size - 4) % 4 != 0) {
                return CallResult(false, KmSecureHardwareCommunicationFailed,
                                  QStringLiteral("Invalid Binder reply header"));
            }
            for (int remaining = size - 4; remaining; remaining -= 4) {
                if (!gbinder_reader_read_int32(reader, Q_NULLPTR)) {
                    return CallResult(false, KmSecureHardwareCommunicationFailed,
                                      QStringLiteral("Truncated Binder reply header"));
                }
            }
            exception = ExceptionNone;
        }
        if (exception == ExceptionNone) {
            return CallResult(true, KmOk);
        }
        if (!gbinder_reader_skip_string16(reader)) {
            return CallResult(false, KmSecureHardwareCommunicationFailed,
                              QStringLiteral("Invalid KeyMint exception message"));
        }
        gint32 stackTraceSize = 0;
        if (!gbinder_reader_read_int32(reader, &stackTraceSize)
                || stackTraceSize != 0) {
            return CallResult(false, KmSecureHardwareCommunicationFailed,
                              QStringLiteral("Unsupported KeyMint exception payload"));
        }
        if (exception == ExceptionServiceSpecific) {
            gint32 keyMintError = KmUnknownError;
            if (!gbinder_reader_read_int32(reader, &keyMintError)) {
                return CallResult(false, KmSecureHardwareCommunicationFailed,
                                  QStringLiteral("KeyMint exception has no error code"));
            }
            return CallResult(true, keyMintError,
                              QStringLiteral("KeyMint error %1").arg(keyMintError));
        }
        return CallResult(false, KmUnknownError,
                          QStringLiteral("Unexpected KeyMint exception %1").arg(exception));
    }

    CallResult deviceCall(quint32 transaction,
                          GBinderLocalRequest *request,
                          GBinderRemoteReply **reply,
                          GBinderReader *reader)
    {
        const CallResult ready = ensureClient();
        if (!ready.succeeded()) {
            return ready;
        }
        return transact(client, transaction, request, reply, reader);
    }

    static CallResult parseFailure(const QString &what)
    {
        return CallResult(false, KmSecureHardwareCommunicationFailed,
                          QStringLiteral("Malformed KeyMint %1 reply").arg(what));
    }

    CallResult getHardwareInfo(qint32 *securityLevel)
    {
        if (!securityLevel) {
            return CallResult(false, KmInvalidArgument,
                              QStringLiteral("Missing KeyMint security-level output"));
        }
        const CallResult ready = ensureClient();
        if (!ready.succeeded()) {
            return ready;
        }
        GBinderLocalRequest *request = gbinder_client_new_request(client);
        if (!request) {
            return CallResult(false, KmUnknownError,
                              QStringLiteral("Unable to allocate getHardwareInfo request"));
        }

        GBinderRemoteReply *reply = Q_NULLPTR;
        GBinderReader reader;
        CallResult result = transact(client, GetHardwareInfoTransaction,
                                     request, &reply, &reader);
        qint32 parsedSecurityLevel = -1;
        if (result.succeeded()) {
            gsize hardwareInfoEnd = 0;
            bool nonNull = false;
            gint32 versionNumber = 0;
            gboolean timestampTokenRequired = false;
            if (!startParcelable(&reader, &hardwareInfoEnd, &nonNull)
                    || !nonNull
                    || !gbinder_reader_read_int32(&reader, &versionNumber)
                    || !gbinder_reader_read_int32(&reader, &parsedSecurityLevel)
                    || !gbinder_reader_skip_string16(&reader)
                    || !gbinder_reader_skip_string16(&reader)
                    || !gbinder_reader_read_bool(&reader,
                                                 &timestampTokenRequired)
                    || !finishParcelable(&reader, hardwareInfoEnd)
                    || !gbinder_reader_at_end(&reader)) {
                result = parseFailure(QStringLiteral("getHardwareInfo"));
            } else if (serializeCapabilitiesResponse(parsedSecurityLevel).isEmpty()) {
                result = CallResult(false, KmHardwareTypeUnavailable,
                                    QStringLiteral("Unsupported KeyMint security level %1")
                                    .arg(parsedSecurityLevel));
            }
        }
        if (reply) {
            gbinder_remote_reply_unref(reply);
        }
        gbinder_local_request_unref(request);
        if (result.succeeded()) {
            *securityLevel = parsedSecurityLevel;
        }
        return result;
    }

    static bool readCharacteristics(GBinderReader *reader,
                                    Characteristics *characteristics)
    {
        gint32 count = 0;
        if (!characteristics || !gbinder_reader_read_int32(reader, &count)
                || count < 0 || count > 16) {
            return false;
        }
        Characteristics parsed;
        for (gint32 i = 0; i < count; ++i) {
            gsize itemEnd = 0;
            bool nonNull = false;
            gint32 securityLevel = 0;
            QVector<Parameter> authorizations;
            if (!startParcelable(reader, &itemEnd, &nonNull)
                    || !nonNull
                    || !gbinder_reader_read_int32(reader, &securityLevel)
                    || !readParameters(reader, &authorizations)
                    || !finishParcelable(reader, itemEnd)) {
                return false;
            }
            if (securityLevel == 0 || securityLevel == 100) {
                parsed.software += authorizations;
            } else if (securityLevel == 1 || securityLevel == 2) {
                parsed.hardware += authorizations;
            } else {
                return false;
            }
        }
        *characteristics = parsed;
        return true;
    }

    static bool readKeyCreation(GBinderReader *reader, KeyCreation *creation)
    {
        gsize resultEnd = 0;
        bool nonNull = false;
        KeyCreation parsed;
        if (!creation
                || !startParcelable(reader, &resultEnd, &nonNull)
                || !nonNull
                || !readByteArray(reader, &parsed.key.rawBlob)
                || parsed.key.rawBlob.isEmpty()
                || !readCharacteristics(reader, &parsed.characteristics)) {
            return false;
        }
        gint32 certificateCount = 0;
        if (!gbinder_reader_read_int32(reader, &certificateCount)
                || certificateCount < 0
                || certificateCount > static_cast<gint32>(MaximumCertificates)) {
            return false;
        }
        for (gint32 i = 0; i < certificateCount; ++i) {
            gsize certificateEnd = 0;
            bool certificateNonNull = false;
            QByteArray certificate;
            if (!startParcelable(reader, &certificateEnd, &certificateNonNull)
                    || !certificateNonNull
                    || !readByteArray(reader, &certificate)
                    || certificate.isEmpty()
                    || !finishParcelable(reader, certificateEnd)) {
                return false;
            }
            parsed.key.certificates.append(certificate);
        }
        if (!finishParcelable(reader, resultEnd)) {
            return false;
        }
        parsed.key.publicKey = extractPublicKey(parsed.key.certificates);
        *creation = parsed;
        return true;
    }

    CallResult generateKey(const QVector<Parameter> &parameters,
                           KeyCreation *creation)
    {
        const CallResult ready = ensureClient();
        if (!ready.succeeded()) {
            return ready;
        }
        GBinderLocalRequest *request = gbinder_client_new_request(client);
        if (!request) {
            return CallResult(false, KmUnknownError,
                              QStringLiteral("Unable to allocate generateKey request"));
        }
        GBinderWriter writer;
        gbinder_local_request_init_writer(request, &writer);
        writeParameters(&writer, parameters);
        gbinder_writer_append_null_parcelable(&writer);

        GBinderRemoteReply *reply = Q_NULLPTR;
        GBinderReader reader;
        CallResult result = transact(client, GenerateKeyTransaction,
                                     request, &reply, &reader);
        if (result.succeeded()
                && (!readKeyCreation(&reader, creation)
                    || !gbinder_reader_at_end(&reader))) {
            result = parseFailure(QStringLiteral("generateKey"));
        }
        if (reply) {
            gbinder_remote_reply_unref(reply);
        }
        gbinder_local_request_unref(request);
        return result;
    }

    CallResult importKey(const QVector<Parameter> &parameters,
                         qint32 format,
                         const QByteArray &keyData,
                         KeyCreation *creation)
    {
        const CallResult ready = ensureClient();
        if (!ready.succeeded()) {
            return ready;
        }
        GBinderLocalRequest *request = gbinder_client_new_request(client);
        if (!request) {
            return CallResult(false, KmUnknownError,
                              QStringLiteral("Unable to allocate importKey request"));
        }
        GBinderWriter writer;
        gbinder_local_request_init_writer(request, &writer);
        writeParameters(&writer, parameters);
        gbinder_writer_append_int32(&writer, format);
        appendByteArray(&writer, keyData);
        gbinder_writer_append_null_parcelable(&writer);

        GBinderRemoteReply *reply = Q_NULLPTR;
        GBinderReader reader;
        CallResult result = transact(client, ImportKeyTransaction,
                                     request, &reply, &reader);
        if (result.succeeded()
                && (!readKeyCreation(&reader, creation)
                    || !gbinder_reader_at_end(&reader))) {
            result = parseFailure(QStringLiteral("importKey"));
        }
        if (reply) {
            gbinder_remote_reply_unref(reply);
        }
        gbinder_local_request_unref(request);
        return result;
    }

    CallResult importWrappedKey(const QByteArray &wrappedKey,
                                const QByteArray &wrappingKey,
                                const QByteArray &maskingKey,
                                const QVector<Parameter> &parameters,
                                quint64 passwordSid,
                                quint64 biometricSid,
                                KeyCreation *creation)
    {
        const CallResult ready = ensureClient();
        if (!ready.succeeded()) {
            return ready;
        }
        GBinderLocalRequest *request = gbinder_client_new_request(client);
        if (!request) {
            return CallResult(false, KmUnknownError,
                              QStringLiteral("Unable to allocate importWrappedKey request"));
        }
        GBinderWriter writer;
        gbinder_local_request_init_writer(request, &writer);
        appendByteArray(&writer, wrappedKey);
        appendByteArray(&writer, wrappingKey);
        appendByteArray(&writer, maskingKey);
        writeParameters(&writer, parameters);
        gbinder_writer_append_int64(&writer, passwordSid);
        gbinder_writer_append_int64(&writer, biometricSid);

        GBinderRemoteReply *reply = Q_NULLPTR;
        GBinderReader reader;
        CallResult result = transact(client, ImportWrappedKeyTransaction,
                                     request, &reply, &reader);
        if (result.succeeded()
                && (!readKeyCreation(&reader, creation)
                    || !gbinder_reader_at_end(&reader))) {
            result = parseFailure(QStringLiteral("importWrappedKey"));
        }
        if (reply) {
            gbinder_remote_reply_unref(reply);
        }
        gbinder_local_request_unref(request);
        return result;
    }

    CallResult addEntropy(const QByteArray &entropy)
    {
        const CallResult ready = ensureClient();
        if (!ready.succeeded()) {
            return ready;
        }
        GBinderLocalRequest *request = gbinder_client_new_request(client);
        if (!request) {
            return CallResult(false, KmUnknownError,
                              QStringLiteral("Unable to allocate entropy request"));
        }
        GBinderWriter writer;
        gbinder_local_request_init_writer(request, &writer);
        appendByteArray(&writer, entropy);
        GBinderRemoteReply *reply = Q_NULLPTR;
        GBinderReader reader;
        CallResult result = transact(client, AddRngEntropyTransaction,
                                     request, &reply, &reader);
        if (result.succeeded() && !gbinder_reader_at_end(&reader)) {
            result = parseFailure(QStringLiteral("addRngEntropy"));
        }
        if (reply) {
            gbinder_remote_reply_unref(reply);
        }
        gbinder_local_request_unref(request);
        return result;
    }

    CallResult deleteKey(const QByteArray &rawKeyBlob)
    {
        const CallResult ready = ensureClient();
        if (!ready.succeeded()) {
            return ready;
        }
        GBinderLocalRequest *request = gbinder_client_new_request(client);
        if (!request) {
            return CallResult(false, KmUnknownError,
                              QStringLiteral("Unable to allocate deleteKey request"));
        }
        GBinderWriter writer;
        gbinder_local_request_init_writer(request, &writer);
        appendByteArray(&writer, rawKeyBlob);
        GBinderRemoteReply *reply = Q_NULLPTR;
        GBinderReader reader;
        CallResult result = transact(client, DeleteKeyTransaction,
                                     request, &reply, &reader);
        if (result.succeeded() && !gbinder_reader_at_end(&reader)) {
            result = parseFailure(QStringLiteral("deleteKey"));
        }
        if (reply) {
            gbinder_remote_reply_unref(reply);
        }
        gbinder_local_request_unref(request);
        return result;
    }

    CallResult upgradeKey(const QByteArray &rawKeyBlob,
                          const QVector<Parameter> &parameters,
                          QByteArray *upgradedBlob)
    {
        const CallResult ready = ensureClient();
        if (!ready.succeeded()) {
            return ready;
        }
        GBinderLocalRequest *request = gbinder_client_new_request(client);
        if (!request) {
            return CallResult(false, KmUnknownError,
                              QStringLiteral("Unable to allocate upgradeKey request"));
        }
        GBinderWriter writer;
        gbinder_local_request_init_writer(request, &writer);
        appendByteArray(&writer, rawKeyBlob);
        writeParameters(&writer, parameters);
        GBinderRemoteReply *reply = Q_NULLPTR;
        GBinderReader reader;
        CallResult result = transact(client, UpgradeKeyTransaction,
                                     request, &reply, &reader);
        if (result.succeeded()
                && (!readByteArray(&reader, upgradedBlob) || upgradedBlob->isEmpty()
                    || !gbinder_reader_at_end(&reader))) {
            result = parseFailure(QStringLiteral("upgradeKey"));
        }
        if (reply) {
            gbinder_remote_reply_unref(reply);
        }
        gbinder_local_request_unref(request);
        return result;
    }

    CallResult keyCharacteristics(const QByteArray &rawKeyBlob,
                                  const QByteArray &applicationId,
                                  const QByteArray &applicationData,
                                  Characteristics *characteristics)
    {
        const CallResult ready = ensureClient();
        if (!ready.succeeded()) {
            return ready;
        }
        GBinderLocalRequest *request = gbinder_client_new_request(client);
        if (!request) {
            return CallResult(false, KmUnknownError,
                              QStringLiteral("Unable to allocate characteristics request"));
        }
        GBinderWriter writer;
        gbinder_local_request_init_writer(request, &writer);
        appendByteArray(&writer, rawKeyBlob);
        appendByteArray(&writer, applicationId);
        appendByteArray(&writer, applicationData);
        GBinderRemoteReply *reply = Q_NULLPTR;
        GBinderReader reader;
        CallResult result = transact(client, GetKeyCharacteristicsTransaction,
                                     request, &reply, &reader);
        if (result.succeeded()
                && (!readCharacteristics(&reader, characteristics)
                    || !gbinder_reader_at_end(&reader))) {
            result = parseFailure(QStringLiteral("getKeyCharacteristics"));
        }
        if (reply) {
            gbinder_remote_reply_unref(reply);
        }
        gbinder_local_request_unref(request);
        return result;
    }

    CallResult beginOperation(qint32 purpose,
                              const QByteArray &rawKeyBlob,
                              const QVector<Parameter> &parameters,
                              const HardwareAuthToken &authToken,
                              BinderOperation **operation,
                              QVector<Parameter> *outputParameters)
    {
        const CallResult ready = ensureClient();
        if (!ready.succeeded()) {
            return ready;
        }
        GBinderLocalRequest *request = gbinder_client_new_request(client);
        if (!request) {
            return CallResult(false, KmUnknownError,
                              QStringLiteral("Unable to allocate begin request"));
        }
        GBinderWriter writer;
        gbinder_local_request_init_writer(request, &writer);
        gbinder_writer_append_int32(&writer, purpose);
        appendByteArray(&writer, rawKeyBlob);
        writeParameters(&writer, parameters);
        writeHardwareAuthToken(&writer, authToken);

        GBinderRemoteReply *reply = Q_NULLPTR;
        GBinderReader reader;
        CallResult result = transact(client, BeginTransaction, request, &reply, &reader);
        BinderOperation *parsed = Q_NULLPTR;
        if (result.succeeded()) {
            gsize beginEnd = 0;
            bool nonNull = false;
            guint64 challenge = 0;
            QVector<Parameter> params;
            GBinderRemoteObject *operationRemote = Q_NULLPTR;
            if (!startParcelable(&reader, &beginEnd, &nonNull)
                    || !nonNull
                    || !gbinder_reader_read_uint64(&reader, &challenge)
                    || !readParameters(&reader, &params)
                    || !(operationRemote = gbinder_reader_read_object(&reader))
                    || !finishParcelable(&reader, beginEnd)
                    || !gbinder_reader_at_end(&reader)) {
                if (operationRemote) {
                    gbinder_remote_object_unref(operationRemote);
                }
                result = parseFailure(QStringLiteral("begin"));
            } else {
                GBinderClient *operationClient = gbinder_client_new(
                            operationRemote, KeyMintOperationInterface);
                if (!operationClient) {
                    gbinder_remote_object_unref(operationRemote);
                    result = CallResult(false, KmSecureHardwareCommunicationFailed,
                                        QStringLiteral("Unable to create KeyMint operation client"));
                } else {
                    parsed = new BinderOperation;
                    parsed->remote = operationRemote;
                    parsed->client = operationClient;
                    parsed->challenge = challenge;
                    if (outputParameters) {
                        *outputParameters = params;
                    }
                }
            }
        }
        if (reply) {
            gbinder_remote_reply_unref(reply);
        }
        gbinder_local_request_unref(request);
        if (result.succeeded()) {
            *operation = parsed;
        } else {
            destroyOperation(parsed, true);
        }
        return result;
    }

    CallResult operationCall(BinderOperation *operation,
                             quint32 transaction,
                             const QByteArray &input,
                             const QByteArray &signature,
                             const HardwareAuthToken &authToken,
                             const QByteArray &confirmation,
                             QByteArray *output)
    {
        if (!operation || !operation->client) {
            return CallResult(true, KmInvalidOperationHandle,
                              QStringLiteral("Unknown KeyMint operation"));
        }
        GBinderLocalRequest *request = gbinder_client_new_request(operation->client);
        if (!request) {
            return CallResult(false, KmUnknownError,
                              QStringLiteral("Unable to allocate operation request"));
        }
        GBinderWriter writer;
        gbinder_local_request_init_writer(request, &writer);
        appendByteArray(&writer, input);
        if (transaction == FinishTransaction) {
            appendByteArray(&writer, signature);
            writeHardwareAuthToken(&writer, authToken);
            gbinder_writer_append_null_parcelable(&writer);
            if (confirmation.isNull()) {
                appendNullByteArray(&writer);
            } else {
                appendByteArray(&writer, confirmation);
            }
        } else {
            writeHardwareAuthToken(&writer, authToken);
            gbinder_writer_append_null_parcelable(&writer);
        }
        GBinderRemoteReply *reply = Q_NULLPTR;
        GBinderReader reader;
        CallResult result = transact(operation->client, transaction,
                                     request, &reply, &reader);
        if (result.succeeded()
                && (!output || !readByteArray(&reader, output)
                    || !gbinder_reader_at_end(&reader))) {
            result = parseFailure(transaction == UpdateTransaction
                                  ? QStringLiteral("update")
                                  : QStringLiteral("finish"));
        }
        if (reply) {
            gbinder_remote_reply_unref(reply);
        }
        gbinder_local_request_unref(request);
        return result;
    }

    CallResult updateAad(BinderOperation *operation,
                         const QByteArray &input,
                         const HardwareAuthToken &authToken)
    {
        if (!operation || !operation->client) {
            return CallResult(true, KmInvalidOperationHandle);
        }
        GBinderLocalRequest *request = gbinder_client_new_request(operation->client);
        if (!request) {
            return CallResult(false, KmUnknownError,
                              QStringLiteral("Unable to allocate updateAad request"));
        }
        GBinderWriter writer;
        gbinder_local_request_init_writer(request, &writer);
        appendByteArray(&writer, input);
        writeHardwareAuthToken(&writer, authToken);
        gbinder_writer_append_null_parcelable(&writer);
        GBinderRemoteReply *reply = Q_NULLPTR;
        GBinderReader reader;
        CallResult result = transact(operation->client, UpdateAadTransaction,
                                     request, &reply, &reader);
        if (result.succeeded() && !gbinder_reader_at_end(&reader)) {
            result = parseFailure(QStringLiteral("updateAad"));
        }
        if (reply) {
            gbinder_remote_reply_unref(reply);
        }
        gbinder_local_request_unref(request);
        return result;
    }

    CallResult abortOperation(BinderOperation *operation)
    {
        if (!operation || !operation->client) {
            return CallResult(true, KmInvalidOperationHandle);
        }
        GBinderLocalRequest *request = gbinder_client_new_request(operation->client);
        if (!request) {
            return CallResult(false, KmUnknownError,
                              QStringLiteral("Unable to allocate abort request"));
        }
        GBinderRemoteReply *reply = Q_NULLPTR;
        GBinderReader reader;
        CallResult result = transact(operation->client, AbortTransaction,
                                     request, &reply, &reader);
        if (result.succeeded() && !gbinder_reader_at_end(&reader)) {
            result = parseFailure(QStringLiteral("abort"));
        }
        if (reply) {
            gbinder_remote_reply_unref(reply);
        }
        gbinder_local_request_unref(request);
        return result;
    }

    CallResult validatePolicy(const QVector<Parameter> &parameters) const
    {
        if (!activeSecureUserId || brokerSecureUserId != activeSecureUserId) {
            return CallResult(true, KmNotConfigured,
                              QStringLiteral("No active Sailfish Gatekeeper identity"));
        }
        if (!policyMatchesIdentity(parameters, activeSecureUserId,
                                   activeFingerprintAuthenticatorId)) {
            return CallResult(true, KmInvalidUserId,
                              QStringLiteral("Key policy contains an inactive authenticator ID"));
        }
        return CallResult(true, KmOk);
    }

    CallResult validateToken(const HardwareAuthToken &token,
                             quint64 expectedChallenge = 0) const
    {
        if (!token.present) {
            return CallResult(true, KmOk);
        }
        if (!activeSecureUserId || brokerSecureUserId != activeSecureUserId) {
            return CallResult(true, KmNotConfigured,
                              QStringLiteral("No active Sailfish Gatekeeper identity"));
        }
        if (!token.timestamp || token.mac.size() != 32
                || !tokenMatchesIdentity(token, activeSecureUserId,
                                         activeFingerprintAuthenticatorId)) {
            return CallResult(true, KmKeyUserNotAuthenticated,
                              QStringLiteral("Invalid Sailfish hardware auth token"));
        }
        if (expectedChallenge && token.challenge != expectedChallenge) {
            return CallResult(true, KmKeyUserNotAuthenticated,
                              QStringLiteral("Hardware auth token has the wrong challenge"));
        }
        return CallResult(true, KmOk);
    }

    QMutex mutex;
    GBinderServiceManager *serviceManager;
    GBinderRemoteObject *remote;
    GBinderClient *client;
    quint64 activeSecureUserId;
    quint64 brokerSecureUserId;
    quint64 activeFingerprintAuthenticatorId;
    quint64 nextOperationHandle;
    QHash<quint64, BinderOperation *> appOperations;
    QHash<QByteArray, MasterOperation *> masterOperations;
    QHash<quint64, QByteArray> masterChallenges;
};

KeyMintBinderClient::KeyMintBinderClient()
    : d(new Private)
{
}

KeyMintBinderClient::~KeyMintBinderClient()
{
    delete d;
}

KeyMintBinderClient::CallResult KeyMintBinderClient::beginCreateMasterKey(
        const QByteArray &rootKey,
        quint32 sailfishUserId,
        quint64 secureUserId,
        const QByteArray &identityEpoch,
        quint64 *challenge,
        QByteArray *operationContext)
{
    QMutexLocker locker(&d->mutex);
    if (rootKey.size() != RootKeySize || !sailfishUserId || !secureUserId
            || identityEpoch.size() != IdentityEpochSize
            || !challenge || !operationContext) {
        return CallResult(true, KmInvalidArgument,
                          QStringLiteral("Invalid Secrets master-key identity"));
    }

    QVector<Parameter> keyParameters;
    keyParameters << scalarParameter(TagPurpose, PurposeEncrypt)
                  << scalarParameter(TagPurpose, PurposeDecrypt)
                  << scalarParameter(TagAlgorithm, AlgorithmAes)
                  << scalarParameter(TagKeySize, 256)
                  << scalarParameter(TagBlockMode, BlockModeGcm)
                  << scalarParameter(TagPadding, PaddingNone)
                  << scalarParameter(TagMinMacLength, GcmTagSize * 8)
                  << scalarParameter(TagUserSecureId, secureUserId)
                  << scalarParameter(TagUserAuthType, AuthenticatorPassword);

    KeyCreation creation;
    CallResult result = d->generateKey(keyParameters, &creation);
    if (!result.succeeded()) {
        return result;
    }
    const QByteArray opaqueKey = serializeOpaqueKey(creation.key);
    if (opaqueKey.isEmpty()) {
        d->deleteKey(creation.key.rawBlob);
        return CallResult(false, KmUnknownError,
                          QStringLiteral("Unable to serialize KeyMint master key"));
    }

    QVector<Parameter> beginParameters;
    beginParameters << scalarParameter(TagBlockMode, BlockModeGcm)
                    << scalarParameter(TagPadding, PaddingNone)
                    << scalarParameter(TagMacLength, GcmTagSize * 8);
    HardwareAuthToken noToken;
    Private::BinderOperation *binderOperation = Q_NULLPTR;
    QVector<Parameter> outputParameters;
    result = d->beginOperation(PurposeEncrypt, creation.key.rawBlob,
                               beginParameters, noToken,
                               &binderOperation, &outputParameters);
    const QByteArray nonce = nonceFromParameters(outputParameters);
    if (!result.succeeded() || !binderOperation || !binderOperation->challenge
            || nonce.size() != GcmNonceSize) {
        Private::destroyOperation(binderOperation, true);
        d->deleteKey(creation.key.rawBlob);
        return result.succeeded()
                ? CallResult(false, KmSecureHardwareCommunicationFailed,
                             QStringLiteral("KeyMint did not return an authenticated GCM operation"))
                : result;
    }

    QByteArray context;
    if (!readRandom(&context, 24)) {
        Private::destroyOperation(binderOperation, true);
        d->deleteKey(creation.key.rawBlob);
        return CallResult(false, KmUnknownError,
                          QStringLiteral("Unable to create master-key operation context"));
    }
    context.prepend(MasterContextMagic);
    while (d->masterOperations.contains(context)) {
        if (!readRandom(&context, 24)) {
            Private::destroyOperation(binderOperation, true);
            d->deleteKey(creation.key.rawBlob);
            return CallResult(false, KmUnknownError,
                              QStringLiteral("Unable to create unique master-key context"));
        }
        context.prepend(MasterContextMagic);
    }
    if (d->masterChallenges.contains(binderOperation->challenge)
            || d->appOperations.contains(binderOperation->challenge)) {
        Private::destroyOperation(binderOperation, true);
        d->deleteKey(creation.key.rawBlob);
        return CallResult(true, KmConcurrentAccessConflict,
                          QStringLiteral("KeyMint challenge collision"));
    }

    Private::MasterOperation *master = new Private::MasterOperation;
    master->context = context;
    master->rootKey = rootKey;
    ::mlock(master->rootKey.data(), master->rootKey.size());
    master->envelope.sailfishUserId = sailfishUserId;
    master->envelope.secureUserId = secureUserId;
    master->envelope.identityEpoch = identityEpoch;
    master->envelope.backendVersion = BackendVersion;
    master->envelope.keyBlob = opaqueKey;
    master->envelope.nonce = nonce;
    master->operation = binderOperation;
    master->create = true;
    d->masterOperations.insert(context, master);
    d->masterChallenges.insert(binderOperation->challenge, context);
    *challenge = binderOperation->challenge;
    *operationContext = context;
    return CallResult(true, KmOk);
}

KeyMintBinderClient::CallResult KeyMintBinderClient::finishCreateMasterKey(
        const QByteArray &operationContext,
        const QByteArray &serializedHardwareAuthToken,
        QByteArray *serializedEnvelope)
{
    QMutexLocker locker(&d->mutex);
    Private::MasterOperation *master = d->masterOperations.value(
                operationContext, Q_NULLPTR);
    HardwareAuthToken token;
    if (!master || !master->create || !serializedEnvelope
            || !parseMasterHardwareAuthToken(serializedHardwareAuthToken, &token)) {
        return CallResult(true, KmInvalidArgument,
                          QStringLiteral("Invalid master-key creation context"));
    }
    if (token.challenge != master->operation->challenge
            || token.userId != master->envelope.secureUserId
            || token.authenticatorType != AuthenticatorPassword) {
        return CallResult(true, KmKeyUserNotAuthenticated,
                          QStringLiteral("Master-key auth token does not match Gatekeeper"));
    }

    CallResult result = d->updateAad(
                master->operation, authenticatedEnvelopeData(master->envelope), token);
    QByteArray encrypted;
    if (result.succeeded()) {
        result = d->operationCall(master->operation, FinishTransaction,
                                  master->rootKey, QByteArray(), token,
                                  QByteArray(), &encrypted);
    }
    if (result.succeeded()
            && encrypted.size() == RootKeySize + GcmTagSize) {
        master->envelope.ciphertext = encrypted.left(RootKeySize);
        master->envelope.authenticationTag = encrypted.right(GcmTagSize);
        *serializedEnvelope = serializeEnvelope(master->envelope);
        if (serializedEnvelope->isEmpty()) {
            result = CallResult(false, KmUnknownError,
                                QStringLiteral("Unable to serialize master-key envelope"));
        }
    } else if (result.succeeded()) {
        result = CallResult(false, KmSecureHardwareCommunicationFailed,
                            QStringLiteral("KeyMint returned an invalid GCM ciphertext"));
    }
    d->masterOperations.remove(operationContext);
    d->masterChallenges.remove(master->operation->challenge);
    if (result.succeeded()) {
        d->activeSecureUserId = master->envelope.secureUserId;
    } else {
        OpaqueKey key;
        if (parseOpaqueKey(master->envelope.keyBlob, &key)) {
            d->deleteKey(key.rawBlob);
        }
    }
    Private::destroyMasterOperation(master, !result.succeeded());
    clearSecret(&encrypted);
    return result;
}

KeyMintBinderClient::CallResult KeyMintBinderClient::beginOpenMasterKey(
        const QByteArray &serializedEnvelope,
        quint64 *challenge,
        QByteArray *operationContext)
{
    QMutexLocker locker(&d->mutex);
    KeyMintEnvelope envelope;
    OpaqueKey key;
    if (!challenge || !operationContext
            || !parseEnvelope(serializedEnvelope, &envelope)
            || !parseOpaqueKey(envelope.keyBlob, &key)) {
        return CallResult(true, KmInvalidKeyBlob,
                          QStringLiteral("Invalid Secrets master-key envelope"));
    }
    QVector<Parameter> beginParameters;
    beginParameters << scalarParameter(TagBlockMode, BlockModeGcm)
                    << scalarParameter(TagPadding, PaddingNone)
                    << blobParameter(TagNonce, envelope.nonce)
                    << scalarParameter(TagMacLength,
                                       envelope.authenticationTag.size() * 8);
    HardwareAuthToken noToken;
    Private::BinderOperation *binderOperation = Q_NULLPTR;
    QVector<Parameter> outputParameters;
    CallResult result = d->beginOperation(PurposeDecrypt, key.rawBlob,
                                          beginParameters, noToken,
                                          &binderOperation, &outputParameters);
    if (!result.succeeded() || !binderOperation || !binderOperation->challenge) {
        Private::destroyOperation(binderOperation, true);
        return result.succeeded()
                ? CallResult(false, KmSecureHardwareCommunicationFailed,
                             QStringLiteral("KeyMint did not return an authenticated operation"))
                : result;
    }

    QByteArray context;
    if (!readRandom(&context, 24)) {
        Private::destroyOperation(binderOperation, true);
        return CallResult(false, KmUnknownError,
                          QStringLiteral("Unable to create master-key operation context"));
    }
    context.prepend(MasterContextMagic);
    if (d->masterOperations.contains(context)
            || d->masterChallenges.contains(binderOperation->challenge)
            || d->appOperations.contains(binderOperation->challenge)) {
        Private::destroyOperation(binderOperation, true);
        return CallResult(true, KmConcurrentAccessConflict,
                          QStringLiteral("KeyMint operation collision"));
    }
    Private::MasterOperation *master = new Private::MasterOperation;
    master->context = context;
    master->envelope = envelope;
    master->operation = binderOperation;
    master->create = false;
    d->masterOperations.insert(context, master);
    d->masterChallenges.insert(binderOperation->challenge, context);
    *challenge = binderOperation->challenge;
    *operationContext = context;
    return CallResult(true, KmOk);
}

KeyMintBinderClient::CallResult KeyMintBinderClient::finishOpenMasterKey(
        const QByteArray &operationContext,
        const QByteArray &serializedHardwareAuthToken,
        QByteArray *rootKey)
{
    QMutexLocker locker(&d->mutex);
    Private::MasterOperation *master = d->masterOperations.value(
                operationContext, Q_NULLPTR);
    HardwareAuthToken token;
    if (!master || master->create || !rootKey
            || !parseMasterHardwareAuthToken(serializedHardwareAuthToken, &token)) {
        return CallResult(true, KmInvalidArgument,
                          QStringLiteral("Invalid master-key open context"));
    }
    if (token.challenge != master->operation->challenge
            || token.userId != master->envelope.secureUserId
            || token.authenticatorType != AuthenticatorPassword) {
        return CallResult(true, KmKeyUserNotAuthenticated,
                          QStringLiteral("Master-key auth token does not match Gatekeeper"));
    }
    CallResult result = d->updateAad(
                master->operation, authenticatedEnvelopeData(master->envelope), token);
    QByteArray encrypted = master->envelope.ciphertext
            + master->envelope.authenticationTag;
    QByteArray decrypted;
    if (result.succeeded()) {
        result = d->operationCall(master->operation, FinishTransaction,
                                  encrypted, QByteArray(), token,
                                  QByteArray(), &decrypted);
    }
    if (result.succeeded() && decrypted.size() == RootKeySize) {
        *rootKey = QByteArray(decrypted.constData(), decrypted.size());
        d->activeSecureUserId = master->envelope.secureUserId;
    } else if (result.succeeded()) {
        result = CallResult(false, KmSecureHardwareCommunicationFailed,
                            QStringLiteral("KeyMint returned an invalid master key"));
    }
    d->masterOperations.remove(operationContext);
    d->masterChallenges.remove(master->operation->challenge);
    Private::destroyMasterOperation(master, !result.succeeded());
    clearSecret(&encrypted);
    clearSecret(&decrypted);
    return result;
}

KeyMintBinderClient::CallResult KeyMintBinderClient::oneShot(
        quint32 operation,
        const QByteArray &request,
        QByteArray *response)
{
    QMutexLocker locker(&d->mutex);
    if (!response) {
        return CallResult(true, KmInvalidArgument);
    }
    response->clear();
    Cursor cursor(request);

    if (operation == CapabilitiesOperation) {
        if (!cursor.atEnd()) {
            return CallResult(true, KmInvalidArgument);
        }
        qint32 securityLevel = -1;
        const CallResult result = d->getHardwareInfo(&securityLevel);
        if (result.succeeded()) {
            *response = serializeCapabilitiesResponse(securityLevel);
        }
        return result;
    }
    if (operation == GenerateOperation || operation == ImportOperation) {
        qint32 format = 0;
        QByteArray serializedParameters;
        QByteArray keyData;
        if ((operation == ImportOperation && !cursor.take(&format))
                || !cursor.takeBlob(&serializedParameters)
                || (operation == ImportOperation
                    && (!cursor.takeBlob(&keyData) || keyData.isEmpty()))
                || !cursor.atEnd()) {
            return CallResult(true, KmInvalidArgument);
        }
        QVector<Parameter> parameters;
        if (!parseAuthSet(serializedParameters, &parameters)) {
            return CallResult(true, KmInvalidArgument);
        }
        CallResult result = d->validatePolicy(parameters);
        if (!result.succeeded()) {
            return result;
        }
        KeyCreation creation;
        result = operation == GenerateOperation
                ? d->generateKey(parameters, &creation)
                : d->importKey(parameters, format, keyData, &creation);
        if (!result.succeeded()) {
            return result;
        }
        const QByteArray opaque = serializeOpaqueKey(creation.key);
        const QByteArray characteristics = serializeCharacteristics(
                    creation.characteristics);
        if (opaque.isEmpty() || characteristics.isEmpty()) {
            d->deleteKey(creation.key.rawBlob);
            return CallResult(false, KmUnknownError,
                              QStringLiteral("Unable to serialize KeyMint key result"));
        }
        appendBlob(response, opaque);
        appendBlob(response, characteristics);
        return CallResult(true, KmOk);
    }
    if (operation == ImportWrappedOperation) {
        QByteArray wrapped;
        QByteArray wrappingOpaque;
        QByteArray masking;
        QByteArray serializedParameters;
        quint64 passwordSid = 0;
        quint64 biometricSid = 0;
        OpaqueKey wrappingKey;
        QVector<Parameter> parameters;
        if (!cursor.takeBlob(&wrapped) || wrapped.isEmpty()
                || !cursor.takeBlob(&wrappingOpaque)
                || !cursor.takeBlob(&masking)
                || !cursor.takeBlob(&serializedParameters)
                || !cursor.take(&passwordSid) || !cursor.take(&biometricSid)
                || !cursor.atEnd()
                || !parseOpaqueKey(wrappingOpaque, &wrappingKey)
                || !parseAuthSet(serializedParameters, &parameters)) {
            return CallResult(true, KmInvalidArgument);
        }
        if (!d->activeSecureUserId
                || d->brokerSecureUserId != d->activeSecureUserId) {
            return CallResult(true, KmNotConfigured);
        }
        if (passwordSid && passwordSid != d->activeSecureUserId) {
            return CallResult(true, KmInvalidUserId,
                              QStringLiteral("Wrapped-key password SID is not the Sailfish SID"));
        }
        if (biometricSid
                && biometricSid != d->activeFingerprintAuthenticatorId) {
            return CallResult(true, KmInvalidUserId,
                              QStringLiteral("Wrapped-key biometric SID is not active"));
        }
        KeyCreation creation;
        CallResult result = d->importWrappedKey(
                    wrapped, wrappingKey.rawBlob, masking, parameters,
                    passwordSid, biometricSid, &creation);
        if (!result.succeeded()) {
            return result;
        }
        const QByteArray opaque = serializeOpaqueKey(creation.key);
        const QByteArray characteristics = serializeCharacteristics(
                    creation.characteristics);
        if (opaque.isEmpty() || characteristics.isEmpty()) {
            d->deleteKey(creation.key.rawBlob);
            return CallResult(false, KmUnknownError,
                              QStringLiteral("Unable to serialize wrapped key result"));
        }
        appendBlob(response, opaque);
        appendBlob(response, characteristics);
        return CallResult(true, KmOk);
    }
    if (operation == ExportOperation) {
        quint32 format = 0;
        QByteArray opaqueData;
        QByteArray applicationId;
        QByteArray applicationData;
        OpaqueKey key;
        if (!cursor.take(&format) || !cursor.takeBlob(&opaqueData)
                || !cursor.takeBlob(&applicationId)
                || !cursor.takeBlob(&applicationData) || !cursor.atEnd()
                || !parseOpaqueKey(opaqueData, &key)) {
            return CallResult(true, KmInvalidKeyBlob);
        }
        Q_UNUSED(applicationId)
        Q_UNUSED(applicationData)
        if (format != 0 || key.publicKey.isEmpty()) {
            return CallResult(true, KmUnsupportedKeyFormat);
        }
        appendBlob(response, key.publicKey);
        return CallResult(true, KmOk);
    }
    if (operation == CharacteristicsOperation) {
        QByteArray opaqueData;
        QByteArray applicationId;
        QByteArray applicationData;
        OpaqueKey key;
        if (!cursor.takeBlob(&opaqueData)
                || !cursor.takeBlob(&applicationId)
                || !cursor.takeBlob(&applicationData) || !cursor.atEnd()
                || !parseOpaqueKey(opaqueData, &key)) {
            return CallResult(true, KmInvalidKeyBlob);
        }
        Characteristics characteristics;
        CallResult result = d->keyCharacteristics(
                    key.rawBlob, applicationId, applicationData, &characteristics);
        if (!result.succeeded()) {
            return result;
        }
        *response = serializeCharacteristics(characteristics);
        return response->isEmpty()
                ? CallResult(false, KmUnknownError,
                             QStringLiteral("Unable to serialize key characteristics"))
                : CallResult(true, KmOk);
    }
    if (operation == DeleteOperation) {
        QByteArray opaqueData;
        OpaqueKey key;
        if (!cursor.takeBlob(&opaqueData) || !cursor.atEnd()
                || !parseOpaqueKey(opaqueData, &key)) {
            return CallResult(true, KmInvalidKeyBlob);
        }
        return d->deleteKey(key.rawBlob);
    }
    if (operation == DeleteAllOperation) {
        // AppSupport deletion is intentionally scoped to records owned by the
        // calling instance.  Calling KeyMint deleteAllKeys here would also
        // invalidate the Sailfish Secrets master key.
        return CallResult(true, KmUnimplemented,
                          QStringLiteral("Global KeyMint deletion is prohibited"));
    }
    if (operation == AddEntropyOperation) {
        QByteArray entropy;
        if (!cursor.takeBlob(&entropy) || !cursor.atEnd()) {
            return CallResult(true, KmInvalidArgument);
        }
        return d->addEntropy(entropy);
    }
    if (operation == UpgradeOperation) {
        QByteArray opaqueData;
        QByteArray serializedParameters;
        OpaqueKey key;
        QVector<Parameter> parameters;
        if (!cursor.takeBlob(&opaqueData)
                || !cursor.takeBlob(&serializedParameters) || !cursor.atEnd()
                || !parseOpaqueKey(opaqueData, &key)
                || !parseAuthSet(serializedParameters, &parameters)) {
            return CallResult(true, KmInvalidKeyBlob);
        }
        QByteArray upgraded;
        CallResult result = d->upgradeKey(key.rawBlob, parameters, &upgraded);
        if (!result.succeeded()) {
            return result;
        }
        key.rawBlob = upgraded;
        const QByteArray upgradedOpaque = serializeOpaqueKey(key);
        if (upgradedOpaque.isEmpty()) {
            return CallResult(false, KmUnknownError,
                              QStringLiteral("Unable to serialize upgraded key"));
        }
        appendBlob(response, upgradedOpaque);
        return CallResult(true, KmOk);
    }
    if (operation == AttestOperation) {
        // A generation-time certificate chain is not an attestation response
        // for a later request and challenge.  Do not return stale certificates
        // until the AIDL attestKey transaction is implemented end to end.
        return CallResult(true, KmUnimplemented,
                          QStringLiteral("KeyMint attestation is not implemented"));
    }
    return CallResult(true, KmUnimplemented);
}

KeyMintBinderClient::CallResult KeyMintBinderClient::begin(
        const QByteArray &request,
        quint64 *operationHandle,
        QByteArray *response)
{
    QMutexLocker locker(&d->mutex);
    Cursor cursor(request);
    quint32 purpose = 0;
    QByteArray opaqueData;
    QByteArray serializedParameters;
    OpaqueKey key;
    QVector<Parameter> parameters;
    HardwareAuthToken token;
    if (!operationHandle || !response || !cursor.take(&purpose)
            || !cursor.takeBlob(&opaqueData)
            || !cursor.takeBlob(&serializedParameters)
            || !parseAppHardwareAuthToken(&cursor, &token) || !cursor.atEnd()
            || !parseOpaqueKey(opaqueData, &key)
            || !parseAuthSet(serializedParameters, &parameters)) {
        return CallResult(true, KmInvalidArgument);
    }
    CallResult result = d->validateToken(token);
    if (!result.succeeded()) {
        return result;
    }
    Private::BinderOperation *operation = Q_NULLPTR;
    QVector<Parameter> outputParameters;
    result = d->beginOperation(purpose, key.rawBlob, parameters, token,
                               &operation, &outputParameters);
    if (!result.succeeded()) {
        return result;
    }
    quint64 handle = operation->challenge;
    if (!handle) {
        do {
            handle = d->nextOperationHandle++;
            if (!d->nextOperationHandle) {
                d->nextOperationHandle = 0x8000000000000001ULL;
            }
        } while (!handle || d->appOperations.contains(handle)
                 || d->masterChallenges.contains(handle));
    }
    if (d->appOperations.contains(handle)
            || d->masterChallenges.contains(handle)) {
        Private::destroyOperation(operation, true);
        return CallResult(true, KmConcurrentAccessConflict,
                          QStringLiteral("KeyMint operation handle collision"));
    }
    d->appOperations.insert(handle, operation);
    *operationHandle = handle;
    *response = serializeAuthSet(outputParameters);
    if (response->isEmpty()) {
        d->appOperations.remove(handle);
        Private::destroyOperation(operation, true);
        return CallResult(false, KmUnknownError,
                          QStringLiteral("Unable to serialize begin parameters"));
    }
    return CallResult(true, KmOk);
}

KeyMintBinderClient::CallResult KeyMintBinderClient::update(
        quint64 operationHandle,
        const QByteArray &request,
        QByteArray *response)
{
    QMutexLocker locker(&d->mutex);
    Private::BinderOperation *operation = d->appOperations.value(
                operationHandle, Q_NULLPTR);
    if (!operation || !response) {
        return CallResult(true, KmInvalidOperationHandle);
    }
    Cursor cursor(request);
    QByteArray serializedParameters;
    QByteArray input;
    QByteArray serializedVerificationToken;
    QVector<Parameter> parameters;
    HardwareAuthToken token;
    if (!cursor.takeBlob(&serializedParameters) || !cursor.takeBlob(&input)
            || !parseAppHardwareAuthToken(&cursor, &token)
            || !cursor.takeBlob(&serializedVerificationToken) || !cursor.atEnd()
            || !parseAuthSet(serializedParameters, &parameters)
            || !emptyVerificationToken(serializedVerificationToken)) {
        return CallResult(true, KmInvalidArgument);
    }
    CallResult result = d->validateToken(token, token.present
                                         ? operation->challenge : 0);
    if (!result.succeeded()) {
        return result;
    }
    for (const QByteArray &aad : associatedData(parameters)) {
        result = d->updateAad(operation, aad, token);
        if (!result.succeeded()) {
            return result;
        }
    }
    QByteArray output;
    if (!input.isEmpty()) {
        result = d->operationCall(operation, UpdateTransaction,
                                  input, QByteArray(), token,
                                  QByteArray(), &output);
    }
    if (!result.succeeded()) {
        return result;
    }
    response->clear();
    appendLittleEndian(response, quint32(input.size()));
    appendBlob(response, serializeAuthSet(QVector<Parameter>()));
    appendBlob(response, output);
    return CallResult(true, KmOk);
}

KeyMintBinderClient::CallResult KeyMintBinderClient::finish(
        quint64 operationHandle,
        const QByteArray &request,
        QByteArray *response)
{
    QMutexLocker locker(&d->mutex);
    Private::BinderOperation *operation = d->appOperations.value(
                operationHandle, Q_NULLPTR);
    if (!operation || !response) {
        return CallResult(true, KmInvalidOperationHandle);
    }
    Cursor cursor(request);
    QByteArray serializedParameters;
    QByteArray input;
    QByteArray signature;
    QByteArray serializedVerificationToken;
    QVector<Parameter> parameters;
    HardwareAuthToken token;
    if (!cursor.takeBlob(&serializedParameters) || !cursor.takeBlob(&input)
            || !cursor.takeBlob(&signature)
            || !parseAppHardwareAuthToken(&cursor, &token)
            || !cursor.takeBlob(&serializedVerificationToken) || !cursor.atEnd()
            || !parseAuthSet(serializedParameters, &parameters)
            || !emptyVerificationToken(serializedVerificationToken)) {
        return CallResult(true, KmInvalidArgument);
    }
    CallResult result = d->validateToken(token, token.present
                                         ? operation->challenge : 0);
    if (!result.succeeded()) {
        return result;
    }
    for (const QByteArray &aad : associatedData(parameters)) {
        result = d->updateAad(operation, aad, token);
        if (!result.succeeded()) {
            return result;
        }
    }
    QByteArray confirmation = confirmationToken(parameters);
    if (confirmation.isEmpty()) {
        confirmation = QByteArray();
    }
    QByteArray output;
    result = d->operationCall(operation, FinishTransaction,
                              input, signature, token, confirmation, &output);
    if (!result.succeeded()) {
        return result;
    }
    d->appOperations.remove(operationHandle);
    Private::destroyOperation(operation, false);
    response->clear();
    appendBlob(response, serializeAuthSet(QVector<Parameter>()));
    appendBlob(response, output);
    return CallResult(true, KmOk);
}

KeyMintBinderClient::CallResult KeyMintBinderClient::abort(quint64 operationHandle)
{
    QMutexLocker locker(&d->mutex);
    Private::BinderOperation *operation = d->appOperations.take(operationHandle);
    if (operation) {
        const CallResult result = d->abortOperation(operation);
        Private::destroyOperation(operation, false);
        return result;
    }
    const QByteArray context = d->masterChallenges.take(operationHandle);
    Private::MasterOperation *master = context.isEmpty()
            ? Q_NULLPTR : d->masterOperations.take(context);
    if (master) {
        const CallResult result = d->abortOperation(master->operation);
        Private::destroyMasterOperation(master, false);
        return result;
    }
    return CallResult(true, KmInvalidOperationHandle);
}

KeyMintBinderClient::CallResult KeyMintBinderClient::deviceLocked(
        bool passwordOnly)
{
    QMutexLocker locker(&d->mutex);
    const CallResult ready = d->ensureClient();
    if (!ready.succeeded()) {
        return ready;
    }
    GBinderLocalRequest *request = gbinder_client_new_request(d->client);
    if (!request) {
        return CallResult(false, KmUnknownError,
                          QStringLiteral("Unable to allocate deviceLocked request"));
    }
    GBinderWriter writer;
    gbinder_local_request_init_writer(request, &writer);
    gbinder_writer_append_bool(&writer, passwordOnly);
    // TEE KeyMint uses its own clock.  A nullable TimeStampToken must be
    // absent; fabricating a zero-filled parcelable would be a different wire
    // value and could weaken monotonic lock-time handling.
    gbinder_writer_append_null_parcelable(&writer);

    GBinderRemoteReply *reply = Q_NULLPTR;
    GBinderReader reader;
    CallResult result = d->transact(d->client, DeviceLockedTransaction,
                                    request, &reply, &reader);
    if (result.succeeded() && !gbinder_reader_at_end(&reader)) {
        result = Private::parseFailure(QStringLiteral("deviceLocked"));
    }
    if (reply) {
        gbinder_remote_reply_unref(reply);
    }
    gbinder_local_request_unref(request);
    return result;
}

KeyMintBinderClient::CallResult KeyMintBinderClient::setAuthenticationState(
        quint64 secureUserId,
        quint64 fingerprintAuthenticatorId)
{
    QMutexLocker locker(&d->mutex);
    if (!secureUserId && fingerprintAuthenticatorId) {
        return CallResult(true, KmInvalidArgument,
                          QStringLiteral("Fingerprint identity has no Gatekeeper SID"));
    }
    if (d->brokerSecureUserId != secureUserId
            || d->activeFingerprintAuthenticatorId
                    != fingerprintAuthenticatorId) {
        d->clearAppOperations(true);
        d->brokerSecureUserId = secureUserId;
        d->activeFingerprintAuthenticatorId = fingerprintAuthenticatorId;
    }
    return CallResult(true, KmOk);
}
