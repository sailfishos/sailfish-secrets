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
#include "Crypto/cipherrequest.h"

#include "Crypto/serialisation_p.h"
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
    int iorigin = 0, ialgorithm = 0, ioperations = 0, icomponentConstraints;
    QByteArray publicKey, privateKey, secretKey;
    QVector<QByteArray> customParameters;
    Key::FilterData filterData;

    in >> name;
    in >> collectionName;

    in >> iorigin;
    in >> ialgorithm;
    in >> ioperations;
    in >> icomponentConstraints;

    in >> publicKey;
    in >> privateKey;
    in >> secretKey;

    in >> customParameters;

    in >> filterData;

    buffer.close();

    Key retn;
    retn.setIdentifier(Key::Identifier(name, collectionName));
    retn.setOrigin(static_cast<Key::Origin>(iorigin));
    retn.setAlgorithm(static_cast<CryptoManager::Algorithm>(ialgorithm));
    retn.setOperations(static_cast<CryptoManager::Operations>(ioperations));
    retn.setComponentConstraints(static_cast<Key::Components>(icomponentConstraints));
    retn.setPublicKey(publicKey);
    retn.setPrivateKey(privateKey);
    retn.setSecretKey(secretKey);
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
    out << static_cast<int>(key.componentConstraints());

    out << key.publicKey();
    out << key.privateKey();
    out << key.secretKey();

    out << key.customParameters();

    if (serialisationMode == Key::LosslessSerialisationMode) {
        out << key.filterData();
    } else {
        out << Key::FilterData();
    }

    buffer.close();

    return byteArray;
}

QDataStream& operator>>(QDataStream& in, CryptoManager::Algorithm &v)
{
    quint32 temp = 0;
    in >> temp;
    v = static_cast<CryptoManager::Algorithm>(temp);
    return in;
}

QDataStream& operator<<(QDataStream& out, const CryptoManager::Algorithm &v)
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

QDataStream& operator>>(QDataStream& in, CryptoManager::BlockMode &v)
{
    quint32 temp = 0;
    in >> temp;
    v = static_cast<CryptoManager::BlockMode>(temp);
    return in;
}

QDataStream& operator<<(QDataStream& out, const CryptoManager::BlockMode &v)
{
    quint32 temp = static_cast<quint32>(v);
    out << temp;
    return out;
}

QDataStream& operator>>(QDataStream& in, CryptoManager::EncryptionPadding &v)
{
    quint32 temp = 0;
    in >> temp;
    v = static_cast<CryptoManager::EncryptionPadding>(temp);
    return in;
}

QDataStream& operator<<(QDataStream& out, const CryptoManager::EncryptionPadding &v)
{
    quint32 temp = static_cast<quint32>(v);
    out << temp;
    return out;
}

QDataStream& operator>>(QDataStream& in, CryptoManager::SignaturePadding &v)
{
    quint32 temp = 0;
    in >> temp;
    v = static_cast<CryptoManager::SignaturePadding>(temp);
    return in;
}

QDataStream& operator<<(QDataStream& out, const CryptoManager::SignaturePadding &v)
{
    quint32 temp = static_cast<quint32>(v);
    out << temp;
    return out;
}

QDataStream& operator>>(QDataStream& in, CryptoManager::DigestFunction &v)
{
    quint32 temp = 0;
    in >> temp;
    v = static_cast<CryptoManager::DigestFunction>(temp);
    return in;
}

QDataStream& operator<<(QDataStream& out, const CryptoManager::DigestFunction &v)
{
    quint32 temp = static_cast<quint32>(v);
    out << temp;
    return out;
}

QDataStream& operator>>(QDataStream& in, CryptoManager::Operation &v)
{
    quint32 temp = 0;
    in >> temp;
    v = static_cast<CryptoManager::Operation>(temp);
    return in;
}

QDataStream& operator<<(QDataStream& out, const CryptoManager::Operation &v)
{
    quint32 temp = static_cast<quint32>(v);
    out << temp;
    return out;
}

QDataStream& operator>>(QDataStream& in, CryptoManager::Operations &v)
{
    quint32 temp = 0;
    in >> temp;
    v = static_cast<CryptoManager::Operations>(temp);
    return in;
}

QDataStream& operator<<(QDataStream& out, const CryptoManager::Operations &v)
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
    QVector<CryptoManager::Algorithm> supportedAlgorithms;
    QMap<CryptoManager::Algorithm, QVector<CryptoManager::BlockMode> > supportedBlockModes;
    QMap<CryptoManager::Algorithm, QVector<CryptoManager::EncryptionPadding> > supportedEncryptionPaddings;
    QMap<CryptoManager::Algorithm, QVector<CryptoManager::SignaturePadding> > supportedSignaturePaddings;
    QMap<CryptoManager::Algorithm, QVector<CryptoManager::DigestFunction> > supportedDigests;
    QMap<CryptoManager::Algorithm, CryptoManager::Operations> supportedOperations;

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

QDBusArgument &operator<<(QDBusArgument &argument, const CryptoManager::Algorithm algorithm)
{
    argument.beginStructure();
    argument << static_cast<int>(algorithm);
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, CryptoManager::Algorithm &algorithm)
{
    int iv = 0;
    argument.beginStructure();
    argument >> iv;
    argument.endStructure();
    algorithm = static_cast<CryptoManager::Algorithm>(iv);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const CryptoManager::BlockMode mode)
{
    argument.beginStructure();
    argument << static_cast<int>(mode);
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, CryptoManager::BlockMode &mode)
{
    int iv = 0;
    argument.beginStructure();
    argument >> iv;
    argument.endStructure();
    mode = static_cast<CryptoManager::BlockMode>(iv);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const CryptoManager::EncryptionPadding padding)
{
    argument.beginStructure();
    argument << static_cast<int>(padding);
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, CryptoManager::EncryptionPadding &padding)
{
    int iv = 0;
    argument.beginStructure();
    argument >> iv;
    argument.endStructure();
    padding = static_cast<CryptoManager::EncryptionPadding>(iv);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const CryptoManager::SignaturePadding padding)
{
    argument.beginStructure();
    argument << static_cast<int>(padding);
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, CryptoManager::SignaturePadding &padding)
{
    int iv = 0;
    argument.beginStructure();
    argument >> iv;
    argument.endStructure();
    padding = static_cast<CryptoManager::SignaturePadding>(iv);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const CryptoManager::DigestFunction digest)
{
    argument.beginStructure();
    argument << static_cast<int>(digest);
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, CryptoManager::DigestFunction &digest)
{
    int iv = 0;
    argument.beginStructure();
    argument >> iv;
    argument.endStructure();
    digest = static_cast<CryptoManager::DigestFunction>(iv);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const CryptoManager::Operation operation)
{
    argument.beginStructure();
    argument << static_cast<int>(operation);
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, CryptoManager::Operation &operation)
{
    int iv = 0;
    argument.beginStructure();
    argument >> iv;
    argument.endStructure();
    operation = static_cast<CryptoManager::Operation>(iv);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const CryptoManager::Operations operations)
{
    argument.beginStructure();
    argument << static_cast<int>(operations);
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, CryptoManager::Operations &operations)
{
    int iv = 0;
    argument.beginStructure();
    argument >> iv;
    argument.endStructure();
    operations = static_cast<CryptoManager::Operations>(iv);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Key::Component component)
{
    argument.beginStructure();
    argument << static_cast<int>(component);
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Key::Component &component)
{
    int iv = 0;
    argument.beginStructure();
    argument >> iv;
    argument.endStructure();
    component = static_cast<Key::Component>(iv);
    return argument;
}

QDBusArgument &operator<<(QDBusArgument &argument, const Key::Components components)
{
    argument.beginStructure();
    argument << static_cast<int>(components);
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, Key::Components &components)
{
    int iv = 0;
    argument.beginStructure();
    argument >> iv;
    argument.endStructure();
    components = static_cast<Key::Components>(iv);
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

QDBusArgument &operator<<(QDBusArgument &argument, const CipherRequest::CipherMode mode)
{
    argument.beginStructure();
    argument << static_cast<int>(mode);
    argument.endStructure();
    return argument;
}

const QDBusArgument &operator>>(const QDBusArgument &argument, CipherRequest::CipherMode &mode)
{
    int iv = 0;
    argument.beginStructure();
    argument >> iv;
    argument.endStructure();
    mode = static_cast<CipherRequest::CipherMode>(iv);
    return argument;
}

} // namespace Crypto

} // namespace Sailfish
