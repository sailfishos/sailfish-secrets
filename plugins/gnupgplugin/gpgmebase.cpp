/*
 * Copyright (C) 2018 Damien Caliste.
 * Contact: Damien Caliste <dcaliste@free.fr>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "gpgmebase.h"
#include "gpgme_p.h"
#include <QTemporaryDir>
#include <QProcess>

using namespace Sailfish::Crypto;

Daemon::Plugins::GnuPGPlugin::GnuPGPlugin(gpgme_protocol_t protocol)
    : CryptoPlugin(), m_protocol(protocol)
{
    gpgme_check_version(NULL);
}

Daemon::Plugins::GnuPGPlugin::~GnuPGPlugin()
{
}

Result Daemon::Plugins::GnuPGPlugin::generateRandomData(quint64 callerIdent,
                                                        const QString &csprngEngineName,
                                                        quint64 numberBytes,
                                                        const QVariantMap &customParameters,
                                                        QByteArray *randomData)
{
    Q_UNUSED(callerIdent);
    Q_UNUSED(csprngEngineName);
    Q_UNUSED(numberBytes);
    Q_UNUSED(customParameters);
    Q_UNUSED(randomData);
    return Result(Result::OperationNotSupportedError,
                  QStringLiteral("The GnuPG plugin doesn't support generation of random data."));
}

Result Daemon::Plugins::GnuPGPlugin::seedRandomDataGenerator(quint64 callerIdent,
                                                             const QString &csprngEngineName,
                                                             const QByteArray &seedData,
                                                             double entropyEstimate,
                                                             const QVariantMap &customParameters)
{
    Q_UNUSED(callerIdent);
    Q_UNUSED(csprngEngineName);
    Q_UNUSED(seedData);
    Q_UNUSED(entropyEstimate);
    Q_UNUSED(customParameters);
    return Result(Result::OperationNotSupportedError,
                  QStringLiteral("The GnuPG plugin doesn't support generation of random data."));
}

Result Daemon::Plugins::GnuPGPlugin::generateInitializationVector(CryptoManager::Algorithm algorithm,
                                                                  CryptoManager::BlockMode blockMode,
                                                                  int keySize,
                                                                  const QVariantMap &customParameters,
                                                                  QByteArray *generatedIV)
{
    Q_UNUSED(algorithm);
    Q_UNUSED(blockMode);
    Q_UNUSED(keySize);
    Q_UNUSED(customParameters);
    Q_UNUSED(generatedIV);
    return Result(Result::OperationNotSupportedError,
                  QStringLiteral("The GnuPG plugin doesn't support generation of initialisation vector."));
}

static Result operationIsValid(CryptoManager::Operations operations,
                               const KeyPairGenerationParameters &kpgParams)
{
    if (!kpgParams.isValid()) {
        return Result(Result::CryptoPluginKeyGenerationError,
                      QStringLiteral("invalid key generation parameters."));
    }
    if (kpgParams.keyPairType() != KeyPairGenerationParameters::KeyPairDsa
        && kpgParams.keyPairType() != KeyPairGenerationParameters::KeyPairRsa
        && kpgParams.keyPairType() != KeyPairGenerationParameters::KeyPairCustom) {
        return Result(Result::CryptoPluginKeyGenerationError,
                      QStringLiteral("unsupported key pair algorithm."));
    }
    if (kpgParams.keyPairType() == KeyPairGenerationParameters::KeyPairDsa
        && (operations & CryptoManager::OperationEncrypt)) {
        return Result(Result::CryptoPluginKeyGenerationError,
                      QStringLiteral("unsupported algorithm for operation."));
    }
    if (kpgParams.keyPairType() == KeyPairGenerationParameters::KeyPairDsa) {
        DsaKeyPairGenerationParameters dkpgp(kpgParams);
        if (dkpgp.modulusLength() != 1024) {
            qCWarning(lcSailfishCryptoPlugin) << "GnuPG only support 1024 bits for DSA algorithm.";
        }
    }
    return Result();
}

struct GPGmeKeyEdit
{
    QByteArray type;
    QByteArray length;
    QByteArray expire;
    bool done;
    GPGmeKeyEdit(const KeyPairGenerationParameters &kpgParams,
                 CryptoManager::Operations operations)
        : expire(""), done(false)
    {
        // Magic numbers are taken from ask_algo() in gnupg2/g10/keygen.c
        switch (kpgParams.keyPairType()) {
        case (KeyPairGenerationParameters::KeyPairDsa):
            type = "2";
            length = "1024";
            break;
        case (KeyPairGenerationParameters::KeyPairRsa):
            if (operations & CryptoManager::OperationSign) {
                type = "5";
            } else if (operations & CryptoManager::OperationEncrypt) {
                type = "6";
            }
            {
                RsaKeyPairGenerationParameters rkpgp(kpgParams);
                length = QByteArray::number(rkpgp.modulusLength());
            }
            break;
        default:
            qCWarning(lcSailfishCryptoPlugin) << QStringLiteral("unsupported algorithm type %1, defaulting to DSA.").arg(kpgParams.keyPairType());
            type = "2";
            length = "1024";
        }
        QVariantMap::ConstIterator expireIt = kpgParams.customParameters().constFind("expire");
        if (expireIt != kpgParams.customParameters().constEnd()) {
            expire = expireIt->toByteArray();
        }
    }
    void setDone()
    {
        done = true;
    }
    bool isDone() const
    {
        return done;
    }
    gpgme_error_t addKeyReply(gpgme_status_code_t status, const char *args, int fd)
    {
        QFile out;
        if (!out.open(fd, QIODevice::ReadWrite)) {
            qCWarning(lcSailfishCryptoPlugin) << "cannot edit:" << out.errorString();
            return GPG_ERR_GENERAL;
        }

        // Special arguments are taken from gnupg2/g10/keygen.c
#define PROMPT QStringLiteral("keyedit.prompt")
#define ALGO   QStringLiteral("keygen.algo")
#define LENGTH QStringLiteral("keygen.size")
#define VALID  QStringLiteral("keygen.valid")
#define SAVE   QStringLiteral("keyedit.save.okay")
        if (status == GPGME_STATUS_GET_LINE && PROMPT.compare(args) == 0
            && !isDone()) {
            out.write("addkey\n");
            return GPG_ERR_NO_ERROR;
        } else if (status == GPGME_STATUS_GET_LINE && ALGO.compare(args) == 0) {
            out.write(type + '\n');
            return GPG_ERR_NO_ERROR;
        } else if (status == GPGME_STATUS_GET_LINE && LENGTH.compare(args) == 0) {
            out.write(length + '\n');
            return GPG_ERR_NO_ERROR;
        } else if (status == GPGME_STATUS_GET_LINE && VALID.compare(args) == 0) {
            out.write(expire + '\n');
            return GPG_ERR_NO_ERROR;
        } else if (status == GPGME_STATUS_KEY_CREATED) {
            setDone();
            return GPG_ERR_NO_ERROR;
        } else if (status == GPGME_STATUS_GET_LINE && PROMPT.compare(args) == 0
                   && isDone()) {
            out.write("quit\n");
            return GPG_ERR_NO_ERROR;
        } else if (status == GPGME_STATUS_GET_BOOL && SAVE.compare(args) == 0) {
            out.write("y\n");
            return GPG_ERR_NO_ERROR;
        }

        return GPG_ERR_NO_ERROR;
    }
};

static gpgme_error_t _edit_cb(void *handle,
                              gpgme_status_code_t status, const char *args, int fd)
{
    GPGmeKeyEdit *params = static_cast<GPGmeKeyEdit*>(handle);
    return params->addKeyReply(status, args, fd);
}

Result Daemon::Plugins::GnuPGPlugin::generateSubkey(const Key &keyTemplate,
                                                    const KeyPairGenerationParameters &kpgParams,
                                                    Key *key,
                                                    const QString &home)
{
    Result check = operationIsValid(keyTemplate.operations(), kpgParams);
    if (check.code() != Result::Succeeded) {
        return check;
    }

    GPGmeContext ctx(m_protocol, home);
    if (!ctx) {
        return Result(Result::CryptoPluginKeyGenerationError, ctx.error());
    }

    GPGmeKey primary = GPGmeKey::fromUid(ctx, keyTemplate.collectionName());
    if (!primary) {
        return Result(Result::StorageError,
                      QStringLiteral("cannot list keys from %1: %2.").arg(keyTemplate.collectionName()).arg(primary.error()));
    }

    GPGmeKeyEdit params(kpgParams, keyTemplate.operations());
    GPGmeData out;
    gpgme_error_t err;
    err = gpgme_op_edit(ctx, primary, _edit_cb, &params, out);
    if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
        return Result(Result::CryptoPluginKeyGenerationError,
                      QStringLiteral("cannot edit key: %1").arg(gpgme_strerror(err)));
    }

    GPGmeKey gkey(ctx, primary.fingerprint());
    if (!gkey) {
        return Result(Result::CryptoPluginKeyGenerationError,
                      QStringLiteral("cannot retrieve new key %1: %2.").arg(primary.fingerprint()).arg(gkey.error()));
    }
    // Assume new key is the last one.
    while (gkey.sub && gkey.sub->next) {
        gkey.sub = gkey.sub->next;
    }
    gkey.toKey(key, this->name());
    if (!home.isEmpty()) {
        key->setFilterData("Ephemeral-Home", home);
    }

    return Result();
}

Result Daemon::Plugins::GnuPGPlugin::generateKey(const Key &keyTemplate,
                                                 const KeyPairGenerationParameters &kpgParams,
                                                 Key *key,
                                                 const QString &home)
{
    Result check = operationIsValid(keyTemplate.operations(), kpgParams);
    if (check.code() != Result::Succeeded) {
        return check;
    }
    QVariantMap::ConstIterator name = kpgParams.customParameters().constFind("name");
    if (m_protocol == GPGME_PROTOCOL_OpenPGP
        && name == kpgParams.customParameters().constEnd()) {
        return Result(Result::CryptoPluginKeyGenerationError,
                      QStringLiteral("missing name custom parameter."));
    }
    QVariantMap::ConstIterator email = kpgParams.customParameters().constFind("email");
    if (email == kpgParams.customParameters().constEnd()) {
        return Result(Result::CryptoPluginKeyGenerationError,
                      QStringLiteral("missing email custom parameter."));
    }

    GPGmeContext ctx(m_protocol, home);
    if (!ctx) {
        return Result(Result::CryptoPluginKeyGenerationError, ctx.error());
    }

    QString gnupgKeyParms = "<GnupgKeyParms format=\"internal\">\n";
    if (kpgParams.keyPairType() == KeyPairGenerationParameters::KeyPairDsa) {
        gnupgKeyParms += "Key-Type: DSA\n";
        gnupgKeyParms += "Key-Length: 1024\n";
        gnupgKeyParms += "Subkey-Type: DSA\n";
        gnupgKeyParms += "Subkey-Length: 1024\n";
    } else if (kpgParams.keyPairType() == KeyPairGenerationParameters::KeyPairRsa) {
        RsaKeyPairGenerationParameters rkpgp(kpgParams);
        gnupgKeyParms += "Key-Type: RSA\n";
        gnupgKeyParms += QStringLiteral("Key-Length: %1\n").arg(rkpgp.modulusLength());
        gnupgKeyParms += "Subkey-Type: RSA\n";
        gnupgKeyParms += QStringLiteral("Subkey-Length: %1\n").arg(rkpgp.modulusLength());
    } else {
        gnupgKeyParms += "Key-Type: default\n";
    }
    if (keyTemplate.operations() & CryptoManager::OperationSign) {
        gnupgKeyParms += "Key-Usage: sign\n";
    }
    else if (keyTemplate.operations() & CryptoManager::OperationEncrypt) {
        gnupgKeyParms += "Key-Usage: encrypt\n";
    }
    QVariantMap::ConstIterator passphrase = kpgParams.customParameters().constFind("passphrase");
    if (passphrase != kpgParams.customParameters().constEnd()) {
        gnupgKeyParms += QStringLiteral("Passphrase: %1\n").arg(passphrase->toString());
    }
    if (m_protocol == GPGME_PROTOCOL_OpenPGP) {
        gnupgKeyParms += QStringLiteral("Name-Real: %1\n").arg(name->toString());
        QVariantMap::ConstIterator comment = kpgParams.customParameters().constFind("comment");
        if (comment != kpgParams.customParameters().constEnd())
            gnupgKeyParms += QStringLiteral("Name-Comment: %1\n").arg(comment->toString());
    }
    gnupgKeyParms += QStringLiteral("Name-Email: %1\n").arg(email->toString());
    QVariantMap::ConstIterator expire = kpgParams.customParameters().constFind("expire");
    if (expire != kpgParams.customParameters().constEnd()) {
        gnupgKeyParms += QStringLiteral("Expire-Date: %1\n").arg(expire->toString());
    }
    gnupgKeyParms += QStringLiteral("</GnupgKeyParms>");

    gpgme_error_t err;
    if (m_protocol == GPGME_PROTOCOL_OpenPGP) {
        err = gpgme_op_genkey(ctx, gnupgKeyParms.toUtf8().constData(), 0, 0);
    } else {
        GPGmeData pub, priv;
        if (!pub || !priv) {
            return Result(Result::CryptoPluginKeyGenerationError,
                          QStringLiteral("cannot create data."));
        }

        err = gpgme_op_genkey(ctx, gnupgKeyParms.toUtf8().constData(), pub, priv);

        // Todo do something with the public data which represent a
        // certificate request for S/MIME. Not implemented yet.
    }
    if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
        return Result(Result::CryptoPluginKeyGenerationError,
                      QStringLiteral("cannot generate key: %1").arg(gpgme_strerror(err)));
    }
    gpgme_genkey_result_t result = gpgme_op_genkey_result(ctx);
    GPGmeKey gkey(ctx, result->fpr);
    if (!gkey) {
        return Result(Result::CryptoPluginKeyGenerationError,
                      QStringLiteral("cannot retrieve new key %1: %2.").arg(result->fpr).arg(gkey.error()));
    }
    gkey.toKey(key, this->name());
    if (!home.isEmpty()) {
        key->setFilterData("Ephemeral-Home", home);
    }

    return Result();
}

Result Daemon::Plugins::GnuPGPlugin::generateKey(const Key &keyTemplate,
                                                 const KeyPairGenerationParameters &kpgParams,
                                                 const KeyDerivationParameters &skdfParams,
                                                 const QVariantMap &customParameters,
                                                 Key *key)
{
    Q_UNUSED(skdfParams);
    Q_UNUSED(customParameters);

    if (keyTemplate.collectionName().isEmpty()) {
        QTemporaryDir tmp;
        if (!tmp.isValid()) {
            return Result(Result::CryptoPluginKeyGenerationError,
                          QStringLiteral("cannot create temporary directory: %1.").arg(tmp.errorString()));
        }
        Result result = generateKey(keyTemplate, kpgParams, key, tmp.path());
        if (result.code() == Result::Succeeded) {
            tmp.setAutoRemove(false);
        }
        return result;
    } else {
        if (keyTemplate.filterData("Ephemeral-Home").isEmpty()) {
            return Result(Result::CryptoPluginKeyGenerationError,
                          QStringLiteral("cannot create subkey for %1: no home in template.").arg(keyTemplate.collectionName()));
        }
        return generateSubkey(keyTemplate, kpgParams,
                              key, keyTemplate.filterData("Ephemeral-Home"));
    }
}

Result Daemon::Plugins::GnuPGPlugin::generateAndStoreKey(const Key &keyTemplate,
                                                         const KeyPairGenerationParameters &kpgParams,
                                                         const KeyDerivationParameters &skdfParams,
                                                         const QVariantMap &customParameters,
                                                         Key *keyMetadata)
{
    Q_UNUSED(skdfParams);
    Q_UNUSED(customParameters);

    if (keyTemplate.collectionName().isEmpty()
        || keyTemplate.collectionName().compare("import") == 0) {
        return generateKey(keyTemplate, kpgParams, keyMetadata, QString());
    } else {
        return generateSubkey(keyTemplate, kpgParams, keyMetadata, QString());
    }
}

Result Daemon::Plugins::GnuPGPlugin::downloadKey(const QString &fingerprint,
                                                 const QStringList &urls,
                                                 Key *importedKey,
                                                 const QString &home)
{
    GPGmeContext ctx(m_protocol, home);
    if (!ctx) {
        return Result(Result::StorageError, ctx.error());
    }
    GPGmeKey gkey(ctx, fingerprint);

    for (QStringList::ConstIterator it = urls.constBegin();
         it != urls.constEnd(); it++) {
        QProcess gpgProcess;
        QStringList arguments;
        arguments << "--batch" << "--no-tty";
        if (!it->isEmpty()) {
            arguments << "--keyserver" << *it;
        }
        if (!gkey) {
            arguments << "--recv-keys" << fingerprint;
        } else {
            arguments << "--refresh" << fingerprint;
        }
        gpgProcess.start("/usr/bin/gpg2", arguments);
        gpgProcess.waitForFinished();
        if (gpgProcess.exitStatus() != QProcess::NormalExit) {
            switch (gpgProcess.error()) {
            case QProcess::FailedToStart:
                return Result(Result::CryptoPluginKeyImportError,
                              QStringLiteral("Cannot fetch key %1 from %2: failed to start.").arg(fingerprint).arg(*it));
            case QProcess::Crashed:
                return Result(Result::CryptoPluginKeyImportError,
                              QStringLiteral("Cannot fetch key %1 from %2: crashed.").arg(fingerprint).arg(*it));
            case QProcess::Timedout:
                return Result(Result::CryptoPluginKeyImportError,
                              QStringLiteral("Cannot fetch key %1 from %2: timed out.").arg(fingerprint).arg(*it));
            default:
                return Result(Result::CryptoPluginKeyImportError,
                              QStringLiteral("Cannot fetch key %1 from %2.").arg(fingerprint).arg(*it));
            }
        }
        if (gpgProcess.exitCode() == 0) {
            GPGmeKey gFetchedKey(ctx, fingerprint);
            if (!gFetchedKey) {
                return Result(Result::CryptoPluginKeyImportError,
                              QStringLiteral("Cannot fetch key %1 from %2: %3.").arg(fingerprint).arg(*it).arg(gFetchedKey.error()));
            }
            gFetchedKey.toKey(importedKey, name());

            return Result();
        }
    }

    return Result(Result::CryptoPluginKeyImportError,
                  QStringLiteral("Cannot fetch key %1: not found from any server.").arg(fingerprint));
}

Result Daemon::Plugins::GnuPGPlugin::importKey(const QByteArray &data,
                                               const QByteArray &passphrase,
                                               const QVariantMap &customParameters,
                                               Key *importedKey,
                                               const QString &home)
{
    Q_UNUSED(passphrase);

    if (customParameters.contains("keyServers")) {
        QStringList urls = customParameters.value("keyServers").toStringList();
        if (urls.isEmpty()) {
            urls << ""; // Will use default servers on empty url.
        }
        return downloadKey(data, urls, importedKey, home);
    }

    GPGmeContext ctx(m_protocol, home);
    if (!ctx) {
        return Result(Result::StorageError, ctx.error());
    }

    GPGmeData gdata(data);
    if (!gdata) {
        return Result(Result::CryptoPluginKeyImportError,
                      QStringLiteral("cannot create data: %1.").arg(gdata.error()));
    }

    gpgme_error_t err;
    err = gpgme_op_import(ctx, gdata);
    if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
        return Result(Result::CryptoPluginKeyImportError,
                      QStringLiteral("cannot import data: %1.").arg(gpgme_strerror(err)));
    }
    gpgme_import_result_t result;
    result = gpgme_op_import_result(ctx);
    if (!result) {
        return Result(Result::CryptoPluginKeyImportError, "cannot get result.");
    }
    gpgme_import_status_t status = result->imports;
    const char *fingerprint = (const char*)0;
    while (status) {
        if (gpgme_err_code(status->result) != GPG_ERR_NO_ERROR) {
            return Result(Result::CryptoPluginKeyImportError,
                          QStringLiteral("failing importing data: %1.").arg(gpgme_strerror(status->result)));
        }
        if (!fingerprint) {
            fingerprint = status->fpr;
        }
        status = status->next;
    }
    if (!fingerprint) {
        return Result(Result::CryptoPluginKeyImportError,
                      QStringLiteral("no key in the imported data."));
    }

    GPGmeKey gFetchedKey(ctx, fingerprint);
    if (!gFetchedKey) {
        return Result(Result::CryptoPluginKeyImportError,
                      QStringLiteral("Cannot import key %1 from data: %2.").arg(fingerprint).arg(gFetchedKey.error()));
    }
    gFetchedKey.toKey(importedKey, name());

    return Result();
}

Result Daemon::Plugins::GnuPGPlugin::importKey(const QByteArray &data,
                                               const QByteArray &passphrase,
                                               const QVariantMap &customParameters,
                                               Key *importedKey)
{
    QTemporaryDir tmp;
    if (!tmp.isValid()) {
        return Result(Result::CryptoPluginKeyImportError,
                      QStringLiteral("cannot create temporary directory: %1.").arg(tmp.errorString()));
    }
    Result result = importKey(data, passphrase, customParameters, importedKey, tmp.path());
    if (result.code() == Result::Succeeded) {
        tmp.setAutoRemove(false);
    }
    return result;
}

Result Daemon::Plugins::GnuPGPlugin::importAndStoreKey(const QByteArray &data,
                                                       const Key &keyTemplate,
                                                       const QByteArray &passphrase,
                                                       const QVariantMap &customParameters,
                                                       Key *keyMetadata)
{
    Q_UNUSED(keyTemplate);

    return importKey(data, passphrase, customParameters, keyMetadata, QString());
}

Result Daemon::Plugins::GnuPGPlugin::storedKey(const Key::Identifier &identifier,
                                               Key::Components keyComponents,
                                               const QVariantMap &customParameters,
                                               Key *key)
{
    GPGmeContext ctx(m_protocol, customParameters.value("Ephemeral-Home",
                                                        QVariant(QString())).toString());
    if (!ctx) {
        return Result(Result::StorageError, ctx.error());
    }

    GPGmeKey gkey(ctx, identifier.name(),
                  (keyComponents & Key::SecretKeyData)
                  ? GPGmeKey::Secret : GPGmeKey::Public);
    if (!gkey) {
        return Result(Result::InvalidKeyIdentifier,
                      Sailfish::Secrets::Result::InvalidSecretError,
                      QStringLiteral("cannot retrieve key %1: %2.").arg(identifier.name()).arg(gkey.error()));
    }
    gkey.toKey(key, name());

    return Result();
}

Result Daemon::Plugins::GnuPGPlugin::storedKeyIdentifiers(const QString &collectionName,
                                                          const QVariantMap &customParameters,
                                                          QVector<Key::Identifier> *identifiers)
{
    if (collectionName.compare("import") == 0) {
        // This is a fake collection to allow importation of new keys,
        // see gpgmestorage().
        return Result();
    }

    GPGmeContext ctx(m_protocol, customParameters.value("Ephemeral-Home",
                                                        QVariant(QString())).toString());
    if (!ctx) {
        return Result(Result::StorageError, ctx.error());
    }

    GPGmeKey key = GPGmeKey::listKeys(ctx, collectionName);
    while (key) {
        while (key.sub) {
            identifiers->append(Key::Identifier(key.sub->fpr, key.collectionName(), name()));
            key.sub = key.sub->next;
        }
        key.next(ctx);
    }
    QString error(key.error());
    if (!error.isEmpty()) {
        return Result(Result::StorageError,
                      QStringLiteral("cannot list keys: %1.").arg(error));
    }

    return Result();
}

Result Daemon::Plugins::GnuPGPlugin::calculateDigest(const QByteArray &data,
                                                     CryptoManager::SignaturePadding padding,
                                                     CryptoManager::DigestFunction digestFunction,
                                                     const QVariantMap &customParameters,
                                                     QByteArray *digest)
{
    Q_UNUSED(data);
    Q_UNUSED(padding);
    Q_UNUSED(digestFunction);
    Q_UNUSED(customParameters);
    Q_UNUSED(digest);
    return Result(Result::OperationNotSupportedError,
                  QStringLiteral("The GnuPG plugin doesn't support diggest."));
}

Result Daemon::Plugins::GnuPGPlugin::operation(CryptoManager::Operation operation,
                                               const Key &key,
                                               const QByteArray &data,
                                               const QVariantMap &customParameters,
                                               QByteArray *output)
{
    Result::ErrorCode errCode;
    if (operation == CryptoManager::OperationSign) {
        errCode = Result::CryptoPluginSigningError;
    } else if (operation == CryptoManager::OperationEncrypt) {
        errCode = Result::CryptoPluginEncryptionError;
    } else {
        return Result(Result::OperationNotSupportedError,
                      QStringLiteral("Operation not supported by GnuPG plugin."));
    }

    if (!output) {
        return Result(errCode, QStringLiteral("missing output argument."));
    }
    output->clear();

    if (key.storagePluginName() != name()) {
        return Result(errCode, QStringLiteral("cannot use a non GnuPG key."));
    }

    GPGmeContext ctx(m_protocol, key.filterData("Ephemeral-Home"));
    if (!ctx) {
        return Result(errCode, ctx.error());
    }
    gpgme_signers_clear(ctx);
    gpgme_set_textmode(ctx, customParameters.value("Text-Mode",
                                                   QVariant(true)).toBool() ? 1 : 0);
    gpgme_set_armor(ctx, customParameters.value("With-Armor",
                                                QVariant(true)).toBool() ? 1 : 0);

    GPGmeData cdata, gdata(data);
    if (!cdata || !gdata) {
        return Result(errCode, QStringLiteral("cannot create cryptographic data."));
    }
    gpgme_error_t err = GPG_ERR_NO_ERROR;
    switch (m_protocol) {
    case GPGME_PROTOCOL_OpenPGP:
        err = gpgme_data_set_encoding(cdata, GPGME_DATA_ENCODING_ARMOR);
        break;
    case GPGME_PROTOCOL_CMS:
        err = gpgme_data_set_encoding(cdata, GPGME_DATA_ENCODING_BASE64);
        break;
    default:
        break;
    }
    if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
        return Result(errCode,
                      QStringLiteral("cannot set encoding on data: %1.").arg(gpgme_strerror(err)));
    }

    GPGmeKey gkey(ctx, key.name(),
                  (operation == CryptoManager::OperationSign)
                  ? GPGmeKey::Secret : GPGmeKey::Public);
    if (!gkey) {
        return Result(Result::InvalidKeyIdentifier,
                      QStringLiteral("cannot retrieve key %1: %2.").arg(key.name()).arg(gkey.error()));
    }

    if (operation == CryptoManager::OperationSign) {
        err = gpgme_signers_add(ctx, gkey);
        if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
            return Result(errCode,
                          QStringLiteral("cannot add key %1: %2.").arg(key.name()).arg(gpgme_strerror(err)));
        }
        err = gpgme_op_sign(ctx, gdata, cdata, GPGME_SIG_MODE_DETACH);
        if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
            return Result(errCode,
                          QStringLiteral("cannot sign: %1.").arg(gpgme_strerror(err)));
        }

        gpgme_sign_result_t res;
        res = gpgme_op_sign_result(ctx);
        if (res->invalid_signers) {
            return Result(errCode,
                          QStringLiteral("found invalid signer %1.").arg(res->invalid_signers->fpr));
        }
        if (!res->signatures || res->signatures->next) {
            return Result(errCode,
                          QStringLiteral("found zero or more than one signature."));
        }

    } else if (operation == CryptoManager::OperationEncrypt) {
        gpgme_key_t recp[2] = {gkey, 0};
        gpgme_encrypt_flags_t trust = GPGME_ENCRYPT_ALWAYS_TRUST;
        if (customParameters.value("Always-Trust",
                                   QVariant(false)).toBool()) {
            trust = gpgme_encrypt_flags_t(0);
        }
        err = gpgme_op_encrypt(ctx, recp, trust, gdata, cdata);
        if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
            return Result(errCode,
                          QStringLiteral("cannot encrypt: %1.").arg(gpgme_strerror(err)));
        }

        gpgme_encrypt_result_t res;
        res = gpgme_op_encrypt_result(ctx);
        if (res->invalid_recipients) {
            return Result(errCode,
                          QStringLiteral("found invalid recipients %1.").arg(res->invalid_recipients->fpr));
        }
    }

    cdata.releaseData(output);
    return Result();
}

Result Daemon::Plugins::GnuPGPlugin::checkOperation(CryptoManager::Operation operation,
                                                    gpgme_ctx_t ctx, const Key &key,
                                                    CryptoManager::VerificationStatus *verificationStatus)
{
    gpgme_verify_result_t verif;
    verif = gpgme_op_verify_result(ctx);
    if (!verif) {
      return (operation == CryptoManager::OperationVerify)
        ? Result(Result::CryptoPluginVerificationError,
                 "cannot retrieve results.")
        : Result();
    }
    gpgme_signature_t signer;
    signer = verif->signatures;
    GPGmeKey gkey(ctx, key.name());
    if (!gkey) {
        return Result(Result::InvalidKeyIdentifier,
                      QStringLiteral("cannot retrieve key %1: %2.").arg(key.name()).arg(gkey.error()));
    }
    while (signer) {
        if (gkey.contains(signer->fpr)) {
            switch (gpgme_err_code(signer->status)) {
            case GPG_ERR_NO_ERROR:
                *verificationStatus = CryptoManager::VerificationSucceeded;
                break;
            case GPG_ERR_SIG_EXPIRED:
                *verificationStatus = CryptoManager::VerificationSignatureExpired;
                break;
            case GPG_ERR_KEY_EXPIRED:
                *verificationStatus = CryptoManager::VerificationKeyExpired;
                break;
            case GPG_ERR_CERT_REVOKED:
                *verificationStatus = CryptoManager::VerificationKeyRevoked;
                break;
            case GPG_ERR_BAD_SIGNATURE:
                *verificationStatus = CryptoManager::VerificationSignatureInvalid;
                break;
            case GPG_ERR_NO_PUBKEY:
                *verificationStatus = CryptoManager::VerificationKeyInvalid;
                break;
            default:
                *verificationStatus = CryptoManager::VerificationFailed;
                break;
            }
        }
        signer = signer->next;
    }

    return Result();
}

Result Daemon::Plugins::GnuPGPlugin::sign(const QByteArray &data,
                                          const Key &key,
                                          CryptoManager::SignaturePadding padding,
                                          CryptoManager::DigestFunction digestFunction,
                                          const QVariantMap &customParameters,
                                          QByteArray *signature)
{
    Q_UNUSED(padding);
    Q_UNUSED(digestFunction);

    return operation(CryptoManager::OperationSign,
                     key, data, customParameters, signature);
}

Result Daemon::Plugins::GnuPGPlugin::verify(const QByteArray &signature,
                                            const QByteArray &data,
                                            const Key &key,
                                            CryptoManager::SignaturePadding padding,
                                            CryptoManager::DigestFunction digestFunction,
                                            const QVariantMap &customParameters,
                                            CryptoManager::VerificationStatus *verificationStatus)
{
    Q_UNUSED(padding);
    Q_UNUSED(digestFunction);
    Q_UNUSED(customParameters);

    if (!verificationStatus) {
        return Result(Result::CryptoPluginVerificationError,
                      QStringLiteral("missing verificationStatus argument."));
    }
    *verificationStatus = CryptoManager::VerificationStatusUnknown;

    if (key.storagePluginName() != name()) {
        return Result(Result::CryptoPluginVerificationError,
                      QStringLiteral("cannot verify with a non GnuPG key."));
    }

    GPGmeData gsig(signature), gdata(data);
    if (!gsig || !gdata) {
        return Result(Result::CryptoPluginVerificationError,
                      QStringLiteral("cannot create signature data."));
    }

    GPGmeContext ctx(m_protocol, key.filterData("Ephemeral-Home"));
    if (!ctx) {
        return Result(Result::CryptoPluginVerificationError, ctx.error());
    }

    gpgme_error_t err;
    err = gpgme_op_verify(ctx, gsig, gdata, NULL);
    if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
        return Result(Result::CryptoPluginVerificationError,
                      QStringLiteral("cannot verify message: %1.").arg(gpgme_strerror(err)));
    }
    return checkOperation(CryptoManager::OperationVerify, ctx, key, verificationStatus);
}

Result Daemon::Plugins::GnuPGPlugin::encrypt(const QByteArray &data,
                                             const QByteArray &iv,
                                             const Key &key,
                                             CryptoManager::BlockMode blockMode,
                                             CryptoManager::EncryptionPadding padding,
                                             const QByteArray &authenticationData,
                                             const QVariantMap &customParameters,
                                             QByteArray *encrypted,
                                             QByteArray *authenticationTag)
{
    Q_UNUSED(iv);
    Q_UNUSED(blockMode);
    Q_UNUSED(padding);
    Q_UNUSED(authenticationData);
    Q_UNUSED(authenticationTag);

    return operation(CryptoManager::OperationEncrypt,
                     key, data, customParameters, encrypted);
}

Result Daemon::Plugins::GnuPGPlugin::decrypt(const QByteArray &data,
                                             const QByteArray &iv,
                                             const Key &key, // or keyreference, i.e. Key(keyName)
                                             CryptoManager::BlockMode blockMode,
                                             CryptoManager::EncryptionPadding padding,
                                             const QByteArray &authenticationData,
                                             const QByteArray &authenticationTag,
                                             const QVariantMap &customParameters,
                                             QByteArray *decrypted,
                                             CryptoManager::VerificationStatus *verificationStatus)
{
    Q_UNUSED(iv);
    Q_UNUSED(blockMode);
    Q_UNUSED(padding);
    Q_UNUSED(authenticationData);
    Q_UNUSED(authenticationTag);
    Q_UNUSED(customParameters);

    if (!verificationStatus) {
        return Result(Result::CryptoPluginDecryptionError,
                      QStringLiteral("missing verificationStatus argument."));
    }
    *verificationStatus = CryptoManager::VerificationStatusUnknown;

    if (key.storagePluginName() != name()) {
        return Result(Result::CryptoPluginDecryptionError,
                      QStringLiteral("cannot decrypt with a non GnuPG key."));
    }

    GPGmeData gdata(data), output;
    if (!gdata || !output) {
        return Result(Result::CryptoPluginDecryptionError,
                      QStringLiteral("cannot create cryptographic data."));
    }

    GPGmeContext ctx(m_protocol, key.filterData("Ephemeral-Home"));
    if (!ctx) {
        return Result(Result::CryptoPluginDecryptionError, ctx.error());
    }

    gpgme_error_t err;
    err = gpgme_op_decrypt_verify(ctx, gdata, output);
    if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
        return Result(Result::CryptoPluginDecryptionError,
                      QStringLiteral("cannot decrypt message: %1.").arg(gpgme_strerror(err)));
    }
    Result verifyResult = checkOperation(CryptoManager::OperationDecrypt,
                                         ctx, key, verificationStatus);
    if (verifyResult.code() != Result::Succeeded) {
      return verifyResult;
    }
    gpgme_decrypt_result_t decrypt;
    decrypt = gpgme_op_decrypt_result(ctx);
    if (!decrypt) {
        return Result(Result::CryptoPluginDecryptionError,
                      "cannot retrieve results.");
    }
    output.releaseData(decrypted);

    return Result();
}

Result Daemon::Plugins::GnuPGPlugin::initializeCipherSession(quint64 clientId,
                                                             const QByteArray &iv,
                                                             const Key &key, // or keyreference, i.e. Key(keyName)
                                                             CryptoManager::Operation operation,
                                                             CryptoManager::BlockMode blockMode,
                                                             CryptoManager::EncryptionPadding encryptionPadding,
                                                             CryptoManager::SignaturePadding signaturePadding,
                                                             CryptoManager::DigestFunction digestFunction,
                                                             const QVariantMap &customParameters,
                                                             quint32 *cipherSessionToken)
{
    Q_UNUSED(clientId);
    Q_UNUSED(iv);
    Q_UNUSED(key);
    Q_UNUSED(operation);
    Q_UNUSED(blockMode);
    Q_UNUSED(encryptionPadding);
    Q_UNUSED(signaturePadding);
    Q_UNUSED(digestFunction);
    Q_UNUSED(customParameters);
    Q_UNUSED(cipherSessionToken);
    return Result(Result::OperationNotSupportedError,
                  QStringLiteral("The GnuPG plugin doesn't support cipher."));
}

Result Daemon::Plugins::GnuPGPlugin::updateCipherSessionAuthentication(quint64 clientId,
                                                                       const QByteArray &authenticationData,
                                                                       const QVariantMap &customParameters,
                                                                       quint32 cipherSessionToken)
{
    Q_UNUSED(clientId);
    Q_UNUSED(authenticationData);
    Q_UNUSED(customParameters);
    Q_UNUSED(cipherSessionToken);
    return Result(Result::OperationNotSupportedError,
                  QStringLiteral("The GnuPG plugin doesn't support cipher."));
}

Result Daemon::Plugins::GnuPGPlugin::updateCipherSession(quint64 clientId,
                                                         const QByteArray &data,
                                                         const QVariantMap &customParameters,
                                                         quint32 cipherSessionToken,
                                                         QByteArray *generatedData)
{
    Q_UNUSED(clientId);
    Q_UNUSED(data);
    Q_UNUSED(cipherSessionToken);
    Q_UNUSED(customParameters);
    Q_UNUSED(generatedData);
    return Result(Result::OperationNotSupportedError,
                  QStringLiteral("The GnuPG plugin doesn't support cipher."));
}

Result Daemon::Plugins::GnuPGPlugin::finalizeCipherSession(quint64 clientId,
                                                           const QByteArray &data,
                                                           const QVariantMap &customParameters,
                                                           quint32 cipherSessionToken,
                                                           QByteArray *generatedData,
                                                           CryptoManager::VerificationStatus *verificationStatus)
{
    Q_UNUSED(clientId);
    Q_UNUSED(data);
    Q_UNUSED(cipherSessionToken);
    Q_UNUSED(customParameters);
    Q_UNUSED(generatedData);
    Q_UNUSED(verificationStatus);
    return Result(Result::OperationNotSupportedError,
                  QStringLiteral("The GnuPG plugin doesn't support cipher."));
}
