/*
 * Copyright (C) 2018 Damien Caliste.
 * Contact: Damien Caliste <dcaliste@free.fr>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef GPGME_P_H
#define GPGME_P_H

#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif
#include <gpgme.h>

#include <Crypto/Plugins/extensionplugins.h>
#include <Crypto/key.h>
#include <QString>
#include <QDebug>
#include <QDateTime>

struct GPGmeContext {
    gpgme_ctx_t ctx;
    gpgme_error_t err;
    GPGmeContext(gpgme_protocol_t protocol, const QString &home = QString())
        : ctx(0), err(0)
    {
        err = gpgme_engine_check_version(protocol);
        if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
            gpgme_engine_info_t info;
            gpgme_error_t err2;
            err2 = gpgme_get_engine_info(&info);
            if (!err2) {
                while (info) {
                    if (info->protocol == protocol) {
                        qCWarning(lcSailfishCryptoPlugin) << "protocol:" << gpgme_get_protocol_name(info->protocol);
                        if (info->file_name && !info->version)
                            qCWarning(lcSailfishCryptoPlugin) << "engine" << info->file_name
                                       << "not installed properly";
                        else if (info->file_name && info->version && info->req_version)
                            qCWarning(lcSailfishCryptoPlugin) << "engine" << info->file_name
                                       << "version" << info->version
                                       << "installed, but at least version"
                                       << info->req_version << "required";
                        else
                            qCWarning(lcSailfishCryptoPlugin) << "unknow issue";
                    }
                    info = info->next;
                }
            } else {
                qCWarning(lcSailfishCryptoPlugin) << "cannot get engine info:" << gpgme_strerror(err2);
            }
            return;
        }

        err = gpgme_new(&ctx);
        if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
            ctx = 0;
            return;
        }
        err = gpgme_set_protocol(ctx, protocol);
        if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
            gpgme_release(ctx);
            ctx = 0;
            return;
        }
        if (home.isEmpty()) {
            return;
        }
        gpgme_engine_info_t info = gpgme_ctx_get_engine_info(ctx);
        while (info && info->protocol != protocol)
            info = info->next;
        if (!info) {
            qCWarning(lcSailfishCryptoPlugin) << "cannot change home.";
            return;
        }
        err = gpgme_ctx_set_engine_info(ctx, protocol, info->file_name,
                                        home.toUtf8().constData());
        if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
            gpgme_release(ctx);
            ctx = 0;
            return;
        }
    }
    ~GPGmeContext()
    {
        if (ctx) {
            gpgme_release(ctx);
        }
    }
    bool operator!()
    {
        return (ctx == 0);
    }
    operator gpgme_ctx_t() const
    {
        return ctx;
    }
    QString error() const
    {
        return (err && gpgme_err_code(err) != GPG_ERR_NO_ERROR)
            ? QString(gpgme_strerror(err)) : QString();
    }
};

struct GPGmeData {
    gpgme_data_t data;
    gpgme_error_t err;
    GPGmeData()
        : data(0), err(0)
    {
        err = gpgme_data_new(&data);
        if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
            data = 0;
        }
    }
    // The data hold by origin are not copied. origin should be valid
    // for the whole life of the created structure.
    GPGmeData(const QByteArray &origin)
        : data(0), err(0)
    {
#define NO_COPY 0
        err = gpgme_data_new_from_mem(&data, origin.constData(),
                                      origin.length(), NO_COPY);
        if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
            data = 0;
        }
    }
    ~GPGmeData()
    {
        if (data) {
            gpgme_data_release(data);
        }
    }
    operator gpgme_data_t() const
    {
        return data;
    }
    bool operator!()
    {
        return (data == 0);
    }
    QString error() const
    {
        return (err && gpgme_err_code(err) != GPG_ERR_NO_ERROR)
            ? QString(gpgme_strerror(err)) : QString();
    }
    void releaseData(QByteArray *output)
    {
        size_t ln;
        char *signData = gpgme_data_release_and_get_mem(data, &ln);
        data = 0;

        *output = QByteArray(signData, ln);
        gpgme_free(signData);
    }
};

struct GPGmeKey {
    gpgme_key_t key;
    gpgme_subkey_t sub;
    gpgme_error_t err;
    enum Level {
        Public,
        Secret
    };
    GPGmeKey(const gpgme_ctx_t ctx, const char *fingerprint, Level level = Public)
        : key(0), sub(0), err(0)
    {
        err = gpgme_get_key(ctx, fingerprint, &key, level == Secret ? 1 : 0);
        if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
            key = 0;
            return;
        }
        if (!key->subkeys) {
            gpgme_key_unref(key);
            key = 0;
            return;
        }
        sub = key->subkeys;
        while (sub && strcmp(fingerprint, sub->fpr))
            sub = sub->next;
    }
    GPGmeKey(const gpgme_ctx_t ctx, const QString &fingerprint, Level level = Public)
        : GPGmeKey(ctx, fingerprint.toLocal8Bit().constData(), level)
    {
    }
    GPGmeKey(const gpgme_ctx_t ctx)
        : key(0), sub(0), err(0)
    {
        next(ctx);
    }
    GPGmeKey(gpgme_error_t err)
        : key(0), sub(0), err(err)
    {
    }
    GPGmeKey(const GPGmeKey &other)
        : key(other.key), sub(other.sub), err(other.err)
    {
        if (key)
            gpgme_key_ref(key);
    }
    ~GPGmeKey()
    {
        if (key) {
            gpgme_key_unref(key);
        }
    }
    static GPGmeKey fromUid(const gpgme_ctx_t ctx, const QString &uid)
    {
        GPGmeKey key = listKeys(ctx, uid);
        GPGmeKey nextKey(ctx);
        if (nextKey) {
            return GPGmeKey(GPG_ERR_DUP_KEY);
        }
        return key;
    }
    static GPGmeKey listKeys(const gpgme_ctx_t ctx, const QString &filter = QString(), Level level = Public)
    {
        gpgme_error_t err;
        err = gpgme_op_keylist_start(ctx, filter.isEmpty()
                                     ? (const char*)0
                                     : filter.toLocal8Bit().constData(),
                                     level == Secret ? 1 : 0);
        if (gpg_err_code(err) == GPG_ERR_NO_ERROR) {
            return GPGmeKey(ctx);
        } else {
            return GPGmeKey(err);
        }
    }
    operator gpgme_key_t() const
    {
        return key;
    }
    bool operator!()
    {
        return (key == 0);
    }
    operator bool()
    {
        return (key != 0);
    }
    QString error() const
    {
        return (err && gpgme_err_code(err) != GPG_ERR_NO_ERROR)
            ? QString(gpgme_strerror(err)) : QString();
    }
    bool contains(const char *fingerprint) const
    {
        if (!key || !fingerprint) {
            return false;
        }

        gpgme_subkey_t subkey = key->subkeys;
        while (subkey) {
            if (!strcmp(subkey->fpr, fingerprint)) {
                return true;
            }
            subkey = subkey->next;
        }
        return false;
    }
    const char* fingerprint() const
    {
        return sub ? sub->fpr : (const char*)0;
    }
    const char* collectionName() const
    {
        return key && key->uids ? key->uids->uid : (const char*)0;
    }
    void toKey(Sailfish::Crypto::Key *output, const QString &pluginName) const
    {
        if (!key || !key->subkeys || !sub) {
            return;
        }

        output->setName(sub->fpr);
        output->setCollectionName(key->uids->uid);
        output->setStoragePluginName(pluginName);
        output->setPublicKey(key->subkeys->fpr);

        QStringList emails;
        gpgme_user_id_t uid = key->uids;
        while (uid) {
            if (uid->email) {
                emails << uid->email;
            }
            uid = uid->next;
        }
        output->setFilterData("User-Emails", emails.join(","));
        output->setFilterData("Expired", sub->expired ? "true" : "false");
        if (sub->expires) {
            output->setFilterData("Expire-Date",
                                  QDateTime::fromMSecsSinceEpoch(sub->expires).toString());
        }
        if (sub->timestamp > 0) {
            output->setFilterData("Creation-Date",
                                  QDateTime::fromMSecsSinceEpoch(sub->timestamp).toString());
        }

        output->setOrigin(Sailfish::Crypto::Key::OriginUnknown);
        output->setSize(key->subkeys->length);
        switch (key->subkeys->pubkey_algo) {
        case (GPGME_PK_RSA_E):
        case (GPGME_PK_RSA_S):
        case (GPGME_PK_RSA):
            output->setAlgorithm(Sailfish::Crypto::CryptoManager::AlgorithmRsa);
            break;
        case (GPGME_PK_ELG_E):
        case (GPGME_PK_ELG):
            output->setAlgorithm(Sailfish::Crypto::CryptoManager::AlgorithmUnknown);
            break;
        case (GPGME_PK_DSA):
            output->setAlgorithm(Sailfish::Crypto::CryptoManager::AlgorithmDsa);
            break;
        };
        Sailfish::Crypto::CryptoManager::Operations op
            = Sailfish::Crypto::CryptoManager::OperationVerify
            | Sailfish::Crypto::CryptoManager::OperationDecrypt;
        if (key->subkeys->can_encrypt) {
            op |= Sailfish::Crypto::CryptoManager::OperationEncrypt;
        }
        if (key->subkeys->can_sign) {
            op |= Sailfish::Crypto::CryptoManager::OperationSign;
        }
        output->setOperations(op);

        output->setPrivateKey("GnuPG");
    }
    void next(const gpgme_ctx_t ctx)
    {
        if (key) {
            gpgme_key_unref(key);
        }
        err = gpgme_op_keylist_next(ctx, &key);
        if (gpg_err_code(err) == GPG_ERR_NO_ERROR) {
            sub = key->subkeys;
        } else {
            key = 0;
            if (gpg_err_code(err) == GPG_ERR_EOF) {
                err = 0;
            }
        }
    }
};

#endif
