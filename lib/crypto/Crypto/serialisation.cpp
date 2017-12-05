/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Crypto/cryptomanager.h"
#include "Crypto/result.h"
#include "Crypto/key.h"
#include "Crypto/certificate.h"
#include "Crypto/extensionplugins.h"

#include "Crypto/key_p.h"

#include <QtDBus/QDBusArgument>

#include <QtCore/QString>
#include <QtCore/QLoggingCategory>
#include <QtCore/QBuffer>
#include <QtCore/QDataStream>
#include <QtCore/QByteArray>

Q_LOGGING_CATEGORY(lcSailfishCryptoSerialisation, "org.sailfishos.crypto.serialisation", QtWarningMsg)

namespace Sailfish {

namespace Crypto {

Key
Key::deserialise(const QByteArray &data, bool *ok)
{
    QBuffer buffer;
    buffer.setData(data);
    buffer.open(QIODevice::ReadOnly);

    QDataStream in(&buffer);

    quint32 magic;
    in >> magic;
    if (magic != 0x4B657900) {
        qCWarning(lcSailfishCryptoSerialisation) << "Cannot deserialise key, bad magic number:" << magic;
        if (ok) {
            *ok = false;
        }
        return Key();
    }

    qint32 version;
    in >> version;
    if (version != 100) {
        qCWarning(lcSailfishCryptoSerialisation) << "Cannot deserialise key, bad version number:" << version;
        if (ok) {
            *ok = false;
        }
        return Key();
    }

    in.setVersion(QDataStream::Qt_5_6);

    QString name, collectionName;
    int iorigin = 0, ialgorithm = 0, ioperations = 0, iblockModes = 0,
        iencryptionPaddings = 0, isignaturePaddings = 0, idigests = 0;
    QByteArray publicKey, privateKey, secretKey;
    QDateTime validityStart, validityEnd;
    QVector<QByteArray> customParameters;
    Key::FilterData filterData;

    in >> name;
    in >> collectionName;

    in >> iorigin;
    in >> ialgorithm;
    in >> ioperations;
    in >> iblockModes;
    in >> iencryptionPaddings;
    in >> isignaturePaddings;
    in >> idigests;

    in >> publicKey;
    in >> privateKey;
    in >> secretKey;

    in >> validityStart;
    in >> validityEnd;

    in >> customParameters;

    in >> filterData;

    buffer.close();

    Key retn;
    retn.setIdentifier(Key::Identifier(name, collectionName));
    retn.setOrigin(static_cast<Key::Origin>(iorigin));
    retn.setAlgorithm(static_cast<Key::Algorithm>(ialgorithm));
    retn.setOperations(static_cast<Key::Operations>(ioperations));
    retn.setBlockModes(static_cast<Key::BlockModes>(iblockModes));
    retn.setEncryptionPaddings(static_cast<Key::EncryptionPaddings>(iencryptionPaddings));
    retn.setSignaturePaddings(static_cast<Key::SignaturePaddings>(isignaturePaddings));
    retn.setDigests(static_cast<Key::Digests>(idigests));
    retn.setPublicKey(publicKey);
    retn.setPrivateKey(privateKey);
    retn.setSecretKey(secretKey);
    retn.setValidityStart(validityStart);
    retn.setValidityEnd(validityEnd);
    retn.setCustomParameters(customParameters);
    retn.setFilterData(filterData);

    if (ok) {
        *ok = true;
    }
    return retn;
}

QByteArray
Key::serialise(const Key &key, Key::SerialisationMode serialisationMode)
{
    QByteArray byteArray;
    QBuffer buffer(&byteArray);
    buffer.open(QIODevice::WriteOnly);

    QDataStream out(&buffer);

    // Write a header with a "magic number" and a version
    out << (quint32)0x4B657900; // Key\0
    out << (qint32)100;         // version 1.0.0

    // Set the output format version
    out.setVersion(QDataStream::Qt_5_6);

    if (serialisationMode == Key::LosslessSerialisationMode) {
        out << key.identifier().name();
        out << key.identifier().collectionName();
    } else {
        out << QString();
        out << QString();
    }

    out << static_cast<int>(key.origin());
    out << static_cast<int>(key.algorithm());
    out << static_cast<int>(key.operations());
    out << static_cast<int>(key.blockModes());
    out << static_cast<int>(key.encryptionPaddings());
    out << static_cast<int>(key.signaturePaddings());
    out << static_cast<int>(key.digests());

    out << key.publicKey();
    out << key.privateKey();
    out << key.secretKey();

    out << key.validityStart();
    out << key.validityEnd();

    out << key.customParameters();

    if (serialisationMode == Key::LosslessSerialisationMode) {
        out << key.filterData();
    } else {
        out << Key::FilterData();
    }

    buffer.close();

    return byteArray;
}

QDataStream& operator>>(QDataStream& in, Key::Algorithm &v)
{
    quint32 temp = 0;
    in >> temp;
    v = static_cast<Key::Algorithm>(temp);
    return in;
}

QDataStream& operator<<(QDataStream& out, const Key::Algorithm &v)
{
    quint32 temp = static_cast<quint32>(v);
    out << temp;
    return out;
}

QDataStream& operator>>(QDataStream& in, Key::Origin &v)
{
    quint32 temp = 0;
    in >> temp;
    v = static_cast<Key::Origin>(temp);
    return in;
}

QDataStream& operator<<(QDataStream& out, const Key::Origin &v)
{
    quint32 temp = static_cast<quint32>(v);
    out << temp;
    return out;
}

QDataStream& operator>>(QDataStream& in, Key::BlockMode &v)
{
    quint32 temp = 0;
    in >> temp;
    v = static_cast<Key::BlockMode>(temp);
    return in;
}

QDataStream& operator<<(QDataStream& out, const Key::BlockMode &v)
{
    quint32 temp = static_cast<quint32>(v);
    out << temp;
    return out;
}

QDataStream& operator>>(QDataStream& in, Key::EncryptionPadding &v)
{
    quint32 temp = 0;
    in >> temp;
    v = static_cast<Key::EncryptionPadding>(temp);
    return in;
}

QDataStream& operator<<(QDataStream& out, const Key::EncryptionPadding &v)
{
    quint32 temp = static_cast<quint32>(v);
    out << temp;
    return out;
}

QDataStream& operator>>(QDataStream& in, Key::SignaturePadding &v)
{
    quint32 temp = 0;
    in >> temp;
    v = static_cast<Key::SignaturePadding>(temp);
    return in;
}

QDataStream& operator<<(QDataStream& out, const Key::SignaturePadding &v)
{
    quint32 temp = static_cast<quint32>(v);
    out << temp;
    return out;
}

QDataStream& operator>>(QDataStream& in, Key::Digest &v)
{
    quint32 temp = 0;
    in >> temp;
    v = static_cast<Key::Digest>(temp);
    return in;
}

QDataStream& operator<<(QDataStream& out, const Key::Digest &v)
{
    quint32 temp = static_cast<quint32>(v);
    out << temp;
    return out;
}

QDataStream& operator>>(QDataStream& in, Key::Operation &v)
{
    quint32 temp = 0;
    in >> temp;
    v = static_cast<Key::Operation>(temp);
    return in;
}

QDataStream& operator<<(QDataStream& out, const Key::Operation &v)
{
    quint32 temp = static_cast<quint32>(v);
    out << temp;
    return out;
}

QDataStream& operator>>(QDataStream& in, Key::BlockModes &v)
{
    quint32 temp = 0;
    in >> temp;
    v = static_cast<Key::BlockModes>(temp);
    return in;
}

QDataStream& operator<<(QDataStream& out, const Key::BlockModes &v)
{
    quint32 temp = static_cast<quint32>(v);
    out << temp;
    return out;
}

QDataStream& operator>>(QDataStream& in, Key::EncryptionPaddings &v)
{
    quint32 temp = 0;
    in >> temp;
    v = static_cast<Key::EncryptionPaddings>(temp);
    return in;
}

QDataStream& operator<<(QDataStream& out, const Key::EncryptionPaddings &v)
{
    quint32 temp = static_cast<quint32>(v);
    out << temp;
    return out;
}

QDataStream& operator>>(QDataStream& in, Key::SignaturePaddings &v)
{
    quint32 temp = 0;
    in >> temp;
    v = static_cast<Key::SignaturePaddings>(temp);
    return in;
}

QDataStream& operator<<(QDataStream& out, const Key::SignaturePaddings &v)
{
    quint32 temp = static_cast<quint32>(v);
    out << temp;
    return out;
}

QDataStream& operator>>(QDataStream& in, Key::Digests &v)
{
    quint32 temp = 0;
    in >> temp;
    v = static_cast<Key::Digests>(temp);
    return in;
}

QDataStream& operator<<(QDataStream& out, const Key::Digests &v)
{
    quint32 temp = static_cast<quint32>(v);
    out << temp;
    return out;
}

QDataStream& operator>>(QDataStream& in, Key::Operations &v)
{
    quint32 temp = 0;
    in >> temp;
    v = static_cast<Key::Operations>(temp);
    return in;
}

QDataStream& operator<<(QDataStream& out, const Key::Operations &v)
{
    quint32 temp = static_cast<quint32>(v);
    out << temp;
    return out;
}

QDataStream& operator>>(QDataStream& in, CryptoPlugin::EncryptionType &v)
{
    quint32 temp = 0;
    in >> temp;
    v = static_cast<CryptoPlugin::EncryptionType>(temp);
    return in;
}

QDataStream& operator<<(QDataStream& out, const CryptoPlugin::EncryptionType &v)
{
    quint32 temp = static_cast<quint32>(v);
    out << temp;
    return out;
}

CryptoPluginInfo
CryptoPluginInfo::deserialise(const QByteArray &data)
{
    QBuffer buffer;
    buffer.setData(data);
    buffer.open(QIODevice::ReadOnly);

    QDataStream in(&buffer);

    quint32 magic;
    in >> magic;
    if (magic != 0x43504900) {
        qCWarning(lcSailfishCryptoSerialisation) << "Cannot deserialise CryptoPluginInfo, bad magic number:" << magic;
        return CryptoPluginInfo();
    }

    qint32 version;
    in >> version;
    if (version != 100) {
        qCWarning(lcSailfishCryptoSerialisation) << "Cannot deserialise CryptoPluginInfo, bad version number:" << version;
        return CryptoPluginInfo();
    }

    in.setVersion(QDataStream::Qt_5_6);

    QString name;
    bool canStoreKeys = false;
    CryptoPlugin::EncryptionType encryptionType = CryptoPlugin::NoEncryption;
    QVector<Key::Algorithm> supportedAlgorithms;
    QMap<Key::Algorithm, Key::BlockModes> supportedBlockModes;
    QMap<Key::Algorithm, Key::EncryptionPaddings> supportedEncryptionPaddings;
    QMap<Key::Algorithm, Key::SignaturePaddings> supportedSignaturePaddings;
    QMap<Key::Algorithm, Key::Digests> supportedDigests;
    QMap<Key::Algorithm, Key::Operations> supportedOperations;

    in >> name;
    in >> canStoreKeys;
    in >> encryptionType;
    in >> supportedAlgorithms;
    in >> supportedBlockModes;
    in >> supportedEncryptionPaddings;
    in >> supportedSignaturePaddings;
    in >> supportedDigests;
    in >> supportedOperations;

    buffer.close();

    CryptoPluginInfo retn;
    retn.setName(name);
    retn.setCanStoreKeys(canStoreKeys);
    retn.setEncryptionType(encryptionType);
    retn.setSupportedAlgorithms(supportedAlgorithms);
    retn.setSupportedBlockModes(supportedBlockModes);
    retn.setSupportedEncryptionPaddings(supportedEncryptionPaddings);
    retn.setSupportedSignaturePaddings(supportedSignaturePaddings);
    retn.setSupportedDigests(supportedDigests);
    retn.setSupportedOperations(supportedOperations);

    return retn;
}

QByteArray
CryptoPluginInfo::serialise(const CryptoPluginInfo &pluginInfo)
{
    QByteArray byteArray;
    QBuffer buffer(&byteArray);
    buffer.open(QIODevice::WriteOnly);

    QDataStream out(&buffer);

    // Write a header with a "magic number" and a version
    out << (quint32)0x43504900; // CPI\0
    out << (qint32)100;         // version 1.0.0

    // Set the output format version
    out.setVersion(QDataStream::Qt_5_6);

    out << pluginInfo.name();
    out << pluginInfo.canStoreKeys();
    out << pluginInfo.encryptionType();
    out << pluginInfo.supportedAlgorithms();
    out << pluginInfo.supportedBlockModes();
    out << pluginInfo.supportedEncryptionPaddings();
    out << pluginInfo.supportedSignaturePaddings();
    out << pluginInfo.supportedDigests();
    out << pluginInfo.supportedOperations();

    buffer.close();

    return byteArray;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Certificate &certificate)
{
    argument.beginStructure();
    argument << static_cast<int>(certificate.type());
    argument << certificate.toEncoded();
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Certificate &certificate)
{
    int itype = 0;
    QByteArray certificatedata;
    argument.beginStructure();
    argument >> itype;
    argument >> certificatedata;
    argument.endStructure();
    certificate = Certificate::fromEncoded(certificatedata, static_cast<Certificate::Type>(itype));
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Key &key)
{
    argument.beginStructure();
    argument << Key::serialise(key);
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Key &key)
{
    QByteArray keydata;
    argument.beginStructure();
    argument >> keydata;
    argument.endStructure();
    key = Key::deserialise(keydata);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Key::Identifier &identifier)
{
    argument.beginStructure();
    argument << identifier.name();
    argument << identifier.collectionName();
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Key::Identifier &identifier)
{
    QString name, collectionName;
    argument.beginStructure();
    argument >> name;
    argument >> collectionName;
    argument.endStructure();
    identifier = Key::Identifier(name, collectionName);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Key::FilterData &filterData)
{
    argument.beginStructure();
    argument << filterData;
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Key::FilterData &filterData)
{
    QMap<QString,QString> data;
    argument.beginStructure();
    argument >> data;
    argument.endStructure();
    filterData = Key::FilterData(data);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Key::Origin origin)
{
    argument.beginStructure();
    argument << static_cast<int>(origin);
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Key::Origin &origin)
{
    int iv = 0;
    argument.beginStructure();
    argument >> iv;
    argument.endStructure();
    origin = static_cast<Key::Origin>(iv);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Key::Algorithm algorithm)
{
    argument.beginStructure();
    argument << static_cast<int>(algorithm);
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Key::Algorithm &algorithm)
{
    int iv = 0;
    argument.beginStructure();
    argument >> iv;
    argument.endStructure();
    algorithm = static_cast<Key::Algorithm>(iv);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Key::BlockMode mode)
{
    argument.beginStructure();
    argument << static_cast<int>(mode);
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Key::BlockMode &mode)
{
    int iv = 0;
    argument.beginStructure();
    argument >> iv;
    argument.endStructure();
    mode = static_cast<Key::BlockMode>(iv);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Key::EncryptionPadding padding)
{
    argument.beginStructure();
    argument << static_cast<int>(padding);
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Key::EncryptionPadding &padding)
{
    int iv = 0;
    argument.beginStructure();
    argument >> iv;
    argument.endStructure();
    padding = static_cast<Key::EncryptionPadding>(iv);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Key::SignaturePadding padding)
{
    argument.beginStructure();
    argument << static_cast<int>(padding);
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Key::SignaturePadding &padding)
{
    int iv = 0;
    argument.beginStructure();
    argument >> iv;
    argument.endStructure();
    padding = static_cast<Key::SignaturePadding>(iv);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Key::Digest digest)
{
    argument.beginStructure();
    argument << static_cast<int>(digest);
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Key::Digest &digest)
{
    int iv = 0;
    argument.beginStructure();
    argument >> iv;
    argument.endStructure();
    digest = static_cast<Key::Digest>(iv);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Key::Operation operation)
{
    argument.beginStructure();
    argument << static_cast<int>(operation);
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Key::Operation &operation)
{
    int iv = 0;
    argument.beginStructure();
    argument >> iv;
    argument.endStructure();
    operation = static_cast<Key::Operation>(iv);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Key::BlockModes modes)
{
    argument.beginStructure();
    argument << static_cast<int>(modes);
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Key::BlockModes &modes)
{
    int iv = 0;
    argument.beginStructure();
    argument >> iv;
    argument.endStructure();
    modes = static_cast<Key::BlockModes>(iv);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Key::EncryptionPaddings paddings)
{
    argument.beginStructure();
    argument << static_cast<int>(paddings);
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Key::EncryptionPaddings &paddings)
{
    int iv = 0;
    argument.beginStructure();
    argument >> iv;
    argument.endStructure();
    paddings = static_cast<Key::EncryptionPaddings>(iv);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Key::SignaturePaddings paddings)
{
    argument.beginStructure();
    argument << static_cast<int>(paddings);
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Key::SignaturePaddings &paddings)
{
    int iv = 0;
    argument.beginStructure();
    argument >> iv;
    argument.endStructure();
    paddings = static_cast<Key::SignaturePaddings>(iv);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Key::Digests digests)
{
    argument.beginStructure();
    argument << static_cast<int>(digests);
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Key::Digests &digests)
{
    int iv = 0;
    argument.beginStructure();
    argument >> iv;
    argument.endStructure();
    digests = static_cast<Key::Digests>(iv);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Key::Operations operations)
{
    argument.beginStructure();
    argument << static_cast<int>(operations);
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Key::Operations &operations)
{
    int iv = 0;
    argument.beginStructure();
    argument >> iv;
    argument.endStructure();
    operations = static_cast<Key::Operations>(iv);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Result &result)
{
    argument.beginStructure();
    argument << static_cast<int>(result.code()) << result.errorCode() << result.storageErrorCode() << result.errorMessage();
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Result &result)
{
    int code = 0;
    int errorCode = 0;
    int storageErrorCode = 0;
    QString message;

    argument.beginStructure();
    argument >> code >> errorCode >> storageErrorCode >> message;
    argument.endStructure();

    result.setCode(static_cast<Result::ResultCode>(code));
    result.setErrorCode(static_cast<Result::ErrorCode>(errorCode));
    result.setStorageErrorCode(storageErrorCode);
    result.setErrorMessage(message);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const CryptoPluginInfo &pluginInfo)
{
    argument.beginStructure();
    argument << CryptoPluginInfo::serialise(pluginInfo);
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, CryptoPluginInfo &pluginInfo)
{
    QByteArray cpidata;
    argument.beginStructure();
    argument >> cpidata;
    argument.endStructure();
    pluginInfo = CryptoPluginInfo::deserialise(cpidata);
    return argument;
}

} // namespace Crypto

} // namespace Sailfish
