/*
 * Copyright (C) 2018 Damien Caliste.
 * Contact: Damien Caliste <dcaliste@free.fr>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "gpgmestorage.h"
#include "gpgme_p.h"
#include <QLoggingCategory>

Q_LOGGING_CATEGORY(lcSailfishSecretsPluginGnuPG,
                   "org.sailfishos.secrets.plugin.gnupg", QtWarningMsg)

using namespace Sailfish::Secrets;

Daemon::Plugins::GnuPGStoragePlugin::GnuPGStoragePlugin(gpgme_protocol_t protocol)
    : EncryptedStoragePlugin(), m_protocol(protocol)
{
    gpgme_check_version(NULL);
}

Daemon::Plugins::GnuPGStoragePlugin::~GnuPGStoragePlugin()
{
}

Result Daemon::Plugins::GnuPGStoragePlugin::collectionNames(QStringList *names)
{
    names->clear();

    GPGmeContext ctx(m_protocol);
    if (!ctx) {
        return Result(Result::DatabaseError, ctx.error());
    }

    gpgme_error_t err;
    err = gpgme_op_keylist_start(ctx, (const char*)0, 0);
    while (!err) {
        gpgme_key_t key;

        err = gpgme_op_keylist_next(ctx, &key);
        if (err) {
            break;
        }

        if (key->uids) {
            names->append(key->uids->uid);
        }

        gpgme_key_unref(key);
    }
    if (gpg_err_code(err) != GPG_ERR_EOF) {
        return Result(Result::DatabaseError,
                      QStringLiteral("cannot list keys: %1.").arg(gpgme_strerror(err)));
    }
    // Append a generic collection name to be able to import keys
    // into a collection that does not exist yet.
    names->append("import");

    return Result();
}

Result Daemon::Plugins::GnuPGStoragePlugin::createCollection(const QString &collectionName,
                                                             const QByteArray &key)
{
    Q_UNUSED(collectionName);
    Q_UNUSED(key);
    return Result(Result::OperationNotSupportedError,
                  QStringLiteral("The GnuPG plugin doesn't support collection creation."));
}

Result Daemon::Plugins::GnuPGStoragePlugin::removeCollection(const QString &collectionName)
{
    GPGmeContext ctx(m_protocol);
    if (!ctx) {
        return Result(Result::DatabaseError, ctx.error());
    }

    gpgme_error_t err;
    err = gpgme_op_keylist_start(ctx, collectionName.toLocal8Bit().constData(), 0);
    if (gpg_err_code(err) != GPG_ERR_NO_ERROR) {
        return Result(Result::DatabaseError,
                      QStringLiteral("cannot list keys from %1: %2.").arg(collectionName).arg(gpgme_strerror(err)));
    }
    GPGmeKey key(ctx);
    if (!key) {
        return Result(Result::DatabaseError,
                      QStringLiteral("cannot get next key for %1: %2.").arg(collectionName).arg(key.error()));
    }
    GPGmeKey keynext(ctx);
    if (keynext) {
        return Result(Result::DatabaseError,
                      QStringLiteral("more than one collection %1.").arg(collectionName));
    }
    return removeSecret(collectionName, key.fingerprint());
}

Result Daemon::Plugins::GnuPGStoragePlugin::isCollectionLocked(const QString &collectionName,
                                                               bool *locked)
{
    Q_UNUSED(collectionName);

    // GnuPG keys are never locked by the plugin, they are locked externally
    // and will be unlocked by the pinentry.
    if (locked) {
        *locked = false;
    }
    return Result();
}

Result Daemon::Plugins::GnuPGStoragePlugin::deriveKeyFromCode(const QByteArray &authenticationCode,
                                                              const QByteArray &salt,
                                                              QByteArray *key)
{
    Q_UNUSED(authenticationCode);
    Q_UNUSED(salt);
    Q_UNUSED(key);
    return Result(Result::OperationNotSupportedError,
                  QStringLiteral("The GnuPG plugin doesn't support encryption key."));
}

Result Daemon::Plugins::GnuPGStoragePlugin::setEncryptionKey(const QString &collectionName,
                                                             const QByteArray &key)
{
    Q_UNUSED(collectionName);
    Q_UNUSED(key);
    return Result(Result::OperationNotSupportedError,
                  QStringLiteral("The GnuPG plugin doesn't support encryption key."));
}


Result Daemon::Plugins::GnuPGStoragePlugin::reencrypt(const QString &collectionName,
                                                      const QByteArray &oldkey,
                                                      const QByteArray &newkey)
{
    Q_UNUSED(collectionName);
    Q_UNUSED(oldkey);
    Q_UNUSED(newkey);
    return Result(Result::OperationNotSupportedError,
                  QStringLiteral("The GnuPG plugin doesn't support encryption key."));
}

Result Daemon::Plugins::GnuPGStoragePlugin::setSecret(const QString &collectionName,
                                                      const QString &secretName,
                                                      const QByteArray &secret,
                                                      const Secret::FilterData &filterData)
{
    Q_UNUSED(collectionName);
    Q_UNUSED(secretName);
    Q_UNUSED(secret);
    Q_UNUSED(filterData);
    return Result(Result::OperationNotSupportedError,
                  QStringLiteral("The GnuPG plugin doesn't support lambda secrets."));
}

Result Daemon::Plugins::GnuPGStoragePlugin::getSecret(const QString &collectionName,
                                                      const QString &secretName,
                                                      QByteArray *secret,
                                                      Secret::FilterData *filterData)
{
    Q_UNUSED(collectionName);
    Q_UNUSED(secretName);
    Q_UNUSED(secret);
    Q_UNUSED(filterData);
    return Result(Result::OperationNotSupportedError,
                  QStringLiteral("The GnuPG plugin doesn't support lambda secrets."));
}

Result Daemon::Plugins::GnuPGStoragePlugin::secretNames(const QString &collectionName,
                                                        QStringList *secretNames)
{
    secretNames->clear();
    if (collectionName.compare("import") == 0) {
        // This is a fake collection to allow importation of new keys,
        // see collectionNames().
        return Result();
    }

    GPGmeContext ctx(m_protocol);
    if (!ctx) {
        return Result(Result::DatabaseError, ctx.error());
    }

    gpgme_error_t err;
    err = gpgme_op_keylist_start(ctx, collectionName.toLocal8Bit().constData(), 0);
    while (!err) {
        gpgme_key_t key;

        err = gpgme_op_keylist_next(ctx, &key);
        if (err) {
            break;
        }

        gpgme_subkey_t sub = key->subkeys;
        while (sub) {
            secretNames->append(sub->fpr);
            sub = sub->next;
        }

        gpgme_key_unref(key);
    }
    if (gpg_err_code(err) != GPG_ERR_EOF) {
        return Result(Result::DatabaseError,
                      QStringLiteral("cannot list keys: %1.").arg(gpgme_strerror(err)));
    }
    if (secretNames->length() == 0) {
        return Result(Result::InvalidCollectionError,
                      QStringLiteral("no collection %1.").arg(collectionName));
    }

    return Result();
}

Result Daemon::Plugins::GnuPGStoragePlugin::findSecrets(const QString &collectionName,
                                                        const Secret::FilterData &filter,
                                                        StoragePlugin::FilterOperator filterOperator,
                                                        QVector<Secret::Identifier> *identifiers)
{
    identifiers->clear();
    if (collectionName.compare("import") == 0) {
        // This is a fake collection to allow importation of new keys,
        // see collectionNames().
        return Result();
    }

    GPGmeContext ctx(m_protocol);
    if (!ctx) {
        return Result(Result::DatabaseError, ctx.error());
    }

    gpgme_error_t err;
    err = gpgme_op_keylist_start(ctx, collectionName.toLocal8Bit().constData(), 0);
    while (!err) {
        GPGmeKey gkey(ctx);
        if (!gkey) {
            break;
        }

        while (gkey.sub) {
            Sailfish::Crypto::Key key;
            gkey.toKey(&key, name());
            bool match = false;
            const Sailfish::Crypto::Key::FilterData &keyData = key.filterData();
            switch (filterOperator) {
            case SecretManager::OperatorOr:
                match = false;
                for (Secret::FilterData::ConstIterator it = filter.constBegin();
                     it != filter.constEnd() && !match; it++) {
                    match = keyData.contains(it.key())
                        && (keyData.value(it.key()).compare(it.value()) == 0);
                }
                break;
            case SecretManager::OperatorAnd:
                match = true;
                for (Secret::FilterData::ConstIterator it = filter.constBegin();
                     it != filter.constEnd() && match; it++) {
                    match = keyData.contains(it.key())
                        && (keyData.value(it.key()).compare(it.value()) == 0);
                }
                break;
            }
            if (match) {
                identifiers->append(Secret::Identifier(key.name(),
                                                       collectionName, name()));
            }
            gkey.sub = gkey.sub->next;
        }
    }
    if (gpg_err_code(err) != GPG_ERR_EOF) {
        return Result(Result::DatabaseError,
                      QStringLiteral("cannot list keys: %1.").arg(gpgme_strerror(err)));
    }

    return Result();
}

Result Daemon::Plugins::GnuPGStoragePlugin::removeSecret(const QString &collectionName,
                                                         const QString &secretName)
{
    if (collectionName.compare("import") == 0) {
        // This is a fake collection to allow importation of new keys,
        // see collectionNames().
        return Result();
    }

    GPGmeContext ctx(m_protocol);
    if (!ctx) {
        return Result(Result::DatabaseError, ctx.error());
    }

    GPGmeKey gkey(ctx, secretName.toLocal8Bit().constData());
    if (!gkey) {
        return Result(Result::DatabaseError, gkey.error());
    }
    if (!collectionName.isEmpty()
        && gkey.key->uids && collectionName.compare(gkey.key->uids->uid)) {
        return Result(Result::DatabaseError,
                      "matching issue with collection name.");
    }

    gpgme_error_t err;
    err = gpgme_op_delete(ctx, gkey, 1);
    if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
        return Result(Result::DatabaseError,
                      QStringLiteral("cannot delete key %1: %2.").arg(secretName).arg(gpgme_strerror(err)));
    }

    return Result();
}

// standalone secret operations.
Result Daemon::Plugins::GnuPGStoragePlugin::setSecret(const QString &secretName,
                                                      const QByteArray &secret,
                                                      const Secret::FilterData &filterData,
                                                      const QByteArray &key)
{
    Q_UNUSED(secretName);
    Q_UNUSED(secret);
    Q_UNUSED(filterData);
    Q_UNUSED(key);
    return Result(Result::OperationNotSupportedError,
                  QStringLiteral("The GnuPG plugin doesn't support lambda secrets."));
}


Result Daemon::Plugins::GnuPGStoragePlugin::accessSecret(const QString &secretName,
                                                         const QByteArray &key,
                                                         QByteArray *secret,
                                                         Secret::FilterData *filterData)
{
    Q_UNUSED(secretName);
    Q_UNUSED(key);
    Q_UNUSED(secret);
    Q_UNUSED(filterData);
    return Result(Result::OperationNotSupportedError,
                  QStringLiteral("The GnuPG plugin doesn't support lambda secrets."));
}

Result Daemon::Plugins::GnuPGStoragePlugin::removeSecret(const QString &secretName)
{
    return removeSecret(QString(), secretName);
}

Result Daemon::Plugins::GnuPGStoragePlugin::reencryptSecret(const QString &secretName,
                                                            const QByteArray &oldkey,
                                                            const QByteArray &newkey)
{
    Q_UNUSED(secretName);
    Q_UNUSED(oldkey);
    Q_UNUSED(newkey);
    return Result(Result::OperationNotSupportedError,
                  QStringLiteral("The GnuPG plugin doesn't support lambda secrets."));
}
