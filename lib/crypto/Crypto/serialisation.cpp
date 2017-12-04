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

Sailfish::Crypto::Key
Sailfish::Crypto::Key::deserialise(const QByteArray &data, bool *ok)
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
        return Sailfish::Crypto::Key();
    }

    qint32 version;
    in >> version;
    if (version != 100) {
        qCWarning(lcSailfishCryptoSerialisation) << "Cannot deserialise key, bad version number:" << version;
        if (ok) {
            *ok = false;
        }
        return Sailfish::Crypto::Key();
    }

    in.setVersion(QDataStream::Qt_5_6);

    QString name, collectionName;
    int iorigin = 0, ialgorithm = 0, ioperations = 0, iblockModes = 0,
        iencryptionPaddings = 0, isignaturePaddings = 0, idigests = 0;
    QByteArray publicKey, privateKey, secretKey;
    QDateTime validityStart, validityEnd;
    QVector<QByteArray> customParameters;
    Sailfish::Crypto::Key::FilterData filterData;

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

    Sailfish::Crypto::Key retn;
    retn.setIdentifier(Sailfish::Crypto::Key::Identifier(name, collectionName));
    retn.setOrigin(static_cast<Sailfish::Crypto::Key::Origin>(iorigin));
    retn.setAlgorithm(static_cast<Sailfish::Crypto::Key::Algorithm>(ialgorithm));
    retn.setOperations(static_cast<Sailfish::Crypto::Key::Operations>(ioperations));
    retn.setBlockModes(static_cast<Sailfish::Crypto::Key::BlockModes>(iblockModes));
    retn.setEncryptionPaddings(static_cast<Sailfish::Crypto::Key::EncryptionPaddings>(iencryptionPaddings));
    retn.setSignaturePaddings(static_cast<Sailfish::Crypto::Key::SignaturePaddings>(isignaturePaddings));
    retn.setDigests(static_cast<Sailfish::Crypto::Key::Digests>(idigests));
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
Sailfish::Crypto::Key::serialise(const Sailfish::Crypto::Key &key, Sailfish::Crypto::Key::SerialisationMode serialisationMode)
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

    if (serialisationMode == Sailfish::Crypto::Key::LosslessSerialisationMode) {
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

    if (serialisationMode == Sailfish::Crypto::Key::LosslessSerialisationMode) {
        out << key.filterData();
    } else {
        out << Sailfish::Crypto::Key::FilterData();
    }

    buffer.close();

    return byteArray;
}

QDataStream& operator>>(QDataStream& in, Sailfish::Crypto::Key::Algorithm &v)
{
    quint32 temp = 0;
    in >> temp;
    v = static_cast<Sailfish::Crypto::Key::Algorithm>(temp);
    return in;
}

QDataStream& operator<<(QDataStream& out, const Sailfish::Crypto::Key::Algorithm &v)
{
    quint32 temp = static_cast<quint32>(v);
    out << temp;
    return out;
}

QDataStream& operator>>(QDataStream& in, Sailfish::Crypto::Key::Origin &v)
{
    quint32 temp = 0;
    in >> temp;
    v = static_cast<Sailfish::Crypto::Key::Origin>(temp);
    return in;
}

QDataStream& operator<<(QDataStream& out, const Sailfish::Crypto::Key::Origin &v)
{
    quint32 temp = static_cast<quint32>(v);
    out << temp;
    return out;
}

QDataStream& operator>>(QDataStream& in, Sailfish::Crypto::Key::BlockMode &v)
{
    quint32 temp = 0;
    in >> temp;
    v = static_cast<Sailfish::Crypto::Key::BlockMode>(temp);
    return in;
}

QDataStream& operator<<(QDataStream& out, const Sailfish::Crypto::Key::BlockMode &v)
{
    quint32 temp = static_cast<quint32>(v);
    out << temp;
    return out;
}

QDataStream& operator>>(QDataStream& in, Sailfish::Crypto::Key::EncryptionPadding &v)
{
    quint32 temp = 0;
    in >> temp;
    v = static_cast<Sailfish::Crypto::Key::EncryptionPadding>(temp);
    return in;
}

QDataStream& operator<<(QDataStream& out, const Sailfish::Crypto::Key::EncryptionPadding &v)
{
    quint32 temp = static_cast<quint32>(v);
    out << temp;
    return out;
}

QDataStream& operator>>(QDataStream& in, Sailfish::Crypto::Key::SignaturePadding &v)
{
    quint32 temp = 0;
    in >> temp;
    v = static_cast<Sailfish::Crypto::Key::SignaturePadding>(temp);
    return in;
}

QDataStream& operator<<(QDataStream& out, const Sailfish::Crypto::Key::SignaturePadding &v)
{
    quint32 temp = static_cast<quint32>(v);
    out << temp;
    return out;
}

QDataStream& operator>>(QDataStream& in, Sailfish::Crypto::Key::Digest &v)
{
    quint32 temp = 0;
    in >> temp;
    v = static_cast<Sailfish::Crypto::Key::Digest>(temp);
    return in;
}

QDataStream& operator<<(QDataStream& out, const Sailfish::Crypto::Key::Digest &v)
{
    quint32 temp = static_cast<quint32>(v);
    out << temp;
    return out;
}

QDataStream& operator>>(QDataStream& in, Sailfish::Crypto::Key::Operation &v)
{
    quint32 temp = 0;
    in >> temp;
    v = static_cast<Sailfish::Crypto::Key::Operation>(temp);
    return in;
}

QDataStream& operator<<(QDataStream& out, const Sailfish::Crypto::Key::Operation &v)
{
    quint32 temp = static_cast<quint32>(v);
    out << temp;
    return out;
}

QDataStream& operator>>(QDataStream& in, Sailfish::Crypto::Key::BlockModes &v)
{
    quint32 temp = 0;
    in >> temp;
    v = static_cast<Sailfish::Crypto::Key::BlockModes>(temp);
    return in;
}

QDataStream& operator<<(QDataStream& out, const Sailfish::Crypto::Key::BlockModes &v)
{
    quint32 temp = static_cast<quint32>(v);
    out << temp;
    return out;
}

QDataStream& operator>>(QDataStream& in, Sailfish::Crypto::Key::EncryptionPaddings &v)
{
    quint32 temp = 0;
    in >> temp;
    v = static_cast<Sailfish::Crypto::Key::EncryptionPaddings>(temp);
    return in;
}

QDataStream& operator<<(QDataStream& out, const Sailfish::Crypto::Key::EncryptionPaddings &v)
{
    quint32 temp = static_cast<quint32>(v);
    out << temp;
    return out;
}

QDataStream& operator>>(QDataStream& in, Sailfish::Crypto::Key::SignaturePaddings &v)
{
    quint32 temp = 0;
    in >> temp;
    v = static_cast<Sailfish::Crypto::Key::SignaturePaddings>(temp);
    return in;
}

QDataStream& operator<<(QDataStream& out, const Sailfish::Crypto::Key::SignaturePaddings &v)
{
    quint32 temp = static_cast<quint32>(v);
    out << temp;
    return out;
}

QDataStream& operator>>(QDataStream& in, Sailfish::Crypto::Key::Digests &v)
{
    quint32 temp = 0;
    in >> temp;
    v = static_cast<Sailfish::Crypto::Key::Digests>(temp);
    return in;
}

QDataStream& operator<<(QDataStream& out, const Sailfish::Crypto::Key::Digests &v)
{
    quint32 temp = static_cast<quint32>(v);
    out << temp;
    return out;
}

QDataStream& operator>>(QDataStream& in, Sailfish::Crypto::Key::Operations &v)
{
    quint32 temp = 0;
    in >> temp;
    v = static_cast<Sailfish::Crypto::Key::Operations>(temp);
    return in;
}

QDataStream& operator<<(QDataStream& out, const Sailfish::Crypto::Key::Operations &v)
{
    quint32 temp = static_cast<quint32>(v);
    out << temp;
    return out;
}

QDataStream& operator>>(QDataStream& in, Sailfish::Crypto::CryptoPlugin::EncryptionType &v)
{
    quint32 temp = 0;
    in >> temp;
    v = static_cast<Sailfish::Crypto::CryptoPlugin::EncryptionType>(temp);
    return in;
}

QDataStream& operator<<(QDataStream& out, const Sailfish::Crypto::CryptoPlugin::EncryptionType &v)
{
    quint32 temp = static_cast<quint32>(v);
    out << temp;
    return out;
}

Sailfish::Crypto::CryptoPluginInfo
Sailfish::Crypto::CryptoPluginInfo::deserialise(const QByteArray &data)
{
    QBuffer buffer;
    buffer.setData(data);
    buffer.open(QIODevice::ReadOnly);

    QDataStream in(&buffer);

    quint32 magic;
    in >> magic;
    if (magic != 0x43504900) {
        qCWarning(lcSailfishCryptoSerialisation) << "Cannot deserialise CryptoPluginInfo, bad magic number:" << magic;
        return Sailfish::Crypto::CryptoPluginInfo();
    }

    qint32 version;
    in >> version;
    if (version != 100) {
        qCWarning(lcSailfishCryptoSerialisation) << "Cannot deserialise CryptoPluginInfo, bad version number:" << version;
        return Sailfish::Crypto::CryptoPluginInfo();
    }

    in.setVersion(QDataStream::Qt_5_6);

    QString name;
    bool canStoreKeys = false;
    Sailfish::Crypto::CryptoPlugin::EncryptionType encryptionType = Sailfish::Crypto::CryptoPlugin::NoEncryption;
    QVector<Sailfish::Crypto::Key::Algorithm> supportedAlgorithms;
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::BlockModes> supportedBlockModes;
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::EncryptionPaddings> supportedEncryptionPaddings;
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::SignaturePaddings> supportedSignaturePaddings;
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::Digests> supportedDigests;
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::Operations> supportedOperations;

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

    Sailfish::Crypto::CryptoPluginInfo retn;
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
Sailfish::Crypto::CryptoPluginInfo::serialise(const Sailfish::Crypto::CryptoPluginInfo &pluginInfo)
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

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Certificate &certificate)
{
    argument.beginStructure();
    argument << static_cast<int>(certificate.type());
    argument << certificate.toEncoded();
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Certificate &certificate)
{
    int itype = 0;
    QByteArray certificatedata;
    argument.beginStructure();
    argument >> itype;
    argument >> certificatedata;
    argument.endStructure();
    certificate = Sailfish::Crypto::Certificate::fromEncoded(certificatedata, static_cast<Sailfish::Crypto::Certificate::Type>(itype));
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key &key)
{
    argument.beginStructure();
    argument << Sailfish::Crypto::Key::serialise(key);
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key &key)
{
    QByteArray keydata;
    argument.beginStructure();
    argument >> keydata;
    argument.endStructure();
    key = Sailfish::Crypto::Key::deserialise(keydata);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::Identifier &identifier)
{
    argument.beginStructure();
    argument << identifier.name();
    argument << identifier.collectionName();
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::Identifier &identifier)
{
    QString name, collectionName;
    argument.beginStructure();
    argument >> name;
    argument >> collectionName;
    argument.endStructure();
    identifier = Sailfish::Crypto::Key::Identifier(name, collectionName);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::FilterData &filterData)
{
    argument.beginStructure();
    argument << filterData;
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::FilterData &filterData)
{
    QMap<QString,QString> data;
    argument.beginStructure();
    argument >> data;
    argument.endStructure();
    filterData = Sailfish::Crypto::Key::FilterData(data);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::Origin origin)
{
    argument.beginStructure();
    argument << static_cast<int>(origin);
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::Origin &origin)
{
    int iv = 0;
    argument.beginStructure();
    argument >> iv;
    argument.endStructure();
    origin = static_cast<Sailfish::Crypto::Key::Origin>(iv);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::Algorithm algorithm)
{
    argument.beginStructure();
    argument << static_cast<int>(algorithm);
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::Algorithm &algorithm)
{
    int iv = 0;
    argument.beginStructure();
    argument >> iv;
    argument.endStructure();
    algorithm = static_cast<Sailfish::Crypto::Key::Algorithm>(iv);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::BlockMode mode)
{
    argument.beginStructure();
    argument << static_cast<int>(mode);
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::BlockMode &mode)
{
    int iv = 0;
    argument.beginStructure();
    argument >> iv;
    argument.endStructure();
    mode = static_cast<Sailfish::Crypto::Key::BlockMode>(iv);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::EncryptionPadding padding)
{
    argument.beginStructure();
    argument << static_cast<int>(padding);
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::EncryptionPadding &padding)
{
    int iv = 0;
    argument.beginStructure();
    argument >> iv;
    argument.endStructure();
    padding = static_cast<Sailfish::Crypto::Key::EncryptionPadding>(iv);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::SignaturePadding padding)
{
    argument.beginStructure();
    argument << static_cast<int>(padding);
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::SignaturePadding &padding)
{
    int iv = 0;
    argument.beginStructure();
    argument >> iv;
    argument.endStructure();
    padding = static_cast<Sailfish::Crypto::Key::SignaturePadding>(iv);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::Digest digest)
{
    argument.beginStructure();
    argument << static_cast<int>(digest);
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::Digest &digest)
{
    int iv = 0;
    argument.beginStructure();
    argument >> iv;
    argument.endStructure();
    digest = static_cast<Sailfish::Crypto::Key::Digest>(iv);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::Operation operation)
{
    argument.beginStructure();
    argument << static_cast<int>(operation);
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::Operation &operation)
{
    int iv = 0;
    argument.beginStructure();
    argument >> iv;
    argument.endStructure();
    operation = static_cast<Sailfish::Crypto::Key::Operation>(iv);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::BlockModes modes)
{
    argument.beginStructure();
    argument << static_cast<int>(modes);
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::BlockModes &modes)
{
    int iv = 0;
    argument.beginStructure();
    argument >> iv;
    argument.endStructure();
    modes = static_cast<Sailfish::Crypto::Key::BlockModes>(iv);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::EncryptionPaddings paddings)
{
    argument.beginStructure();
    argument << static_cast<int>(paddings);
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::EncryptionPaddings &paddings)
{
    int iv = 0;
    argument.beginStructure();
    argument >> iv;
    argument.endStructure();
    paddings = static_cast<Sailfish::Crypto::Key::EncryptionPaddings>(iv);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::SignaturePaddings paddings)
{
    argument.beginStructure();
    argument << static_cast<int>(paddings);
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::SignaturePaddings &paddings)
{
    int iv = 0;
    argument.beginStructure();
    argument >> iv;
    argument.endStructure();
    paddings = static_cast<Sailfish::Crypto::Key::SignaturePaddings>(iv);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::Digests digests)
{
    argument.beginStructure();
    argument << static_cast<int>(digests);
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::Digests &digests)
{
    int iv = 0;
    argument.beginStructure();
    argument >> iv;
    argument.endStructure();
    digests = static_cast<Sailfish::Crypto::Key::Digests>(iv);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::Operations operations)
{
    argument.beginStructure();
    argument << static_cast<int>(operations);
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::Operations &operations)
{
    int iv = 0;
    argument.beginStructure();
    argument >> iv;
    argument.endStructure();
    operations = static_cast<Sailfish::Crypto::Key::Operations>(iv);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Result &result)
{
    argument.beginStructure();
    argument << static_cast<int>(result.code()) << result.errorCode() << result.storageErrorCode() << result.errorMessage();
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Result &result)
{
    int code = 0;
    int errorCode = 0;
    int storageErrorCode = 0;
    QString message;

    argument.beginStructure();
    argument >> code >> errorCode >> storageErrorCode >> message;
    argument.endStructure();

    result.setCode(static_cast<Sailfish::Crypto::Result::ResultCode>(code));
    result.setErrorCode(static_cast<Sailfish::Crypto::Result::ErrorCode>(errorCode));
    result.setStorageErrorCode(storageErrorCode);
    result.setErrorMessage(message);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::CryptoPluginInfo &pluginInfo)
{
    argument.beginStructure();
    argument << Sailfish::Crypto::CryptoPluginInfo::serialise(pluginInfo);
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::CryptoPluginInfo &pluginInfo)
{
    QByteArray cpidata;
    argument.beginStructure();
    argument >> cpidata;
    argument.endStructure();
    pluginInfo = Sailfish::Crypto::CryptoPluginInfo::deserialise(cpidata);
    return argument;
}

} // namespace Crypto

} // namespace Sailfish
