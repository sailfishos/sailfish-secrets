/*
 * Copyright (C) 2018 Damien Caliste.
 * Contact: Damien Caliste <dcaliste@free.fr>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "gpgmestorage.h"
#include "gpgme_p.h"
#include <QFile>

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

    GPGmeKey key = GPGmeKey::listKeys(ctx);
    while (key) {
        if (key.collectionName()) {
            names->append(key.collectionName());
        }
        key.next(ctx);
    }
    QString error(key.error());
    if (!error.isEmpty()) {
        return Result(Result::DatabaseError,
                      QStringLiteral("cannot list keys: %1.").arg(error));
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
    return removeSecret(collectionName, QString());
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

    GPGmeKey key = GPGmeKey::listKeys(ctx, collectionName);
    while (key) {
        while (key.sub) {
            secretNames->append(key.sub->fpr);
            key.sub = key.sub->next;
        }
        key.next(ctx);
    }
    QString error(key.error());
    if (!error.isEmpty()) {
        return Result(Result::DatabaseError,
                      QStringLiteral("cannot list keys: %1.").arg(error));
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

    GPGmeKey gkey = GPGmeKey::listKeys(ctx, collectionName);
    while (gkey) {
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
        gkey.next(ctx);
    }
    QString error(gkey.error());
    if (!error.isEmpty()) {
        return Result(Result::DatabaseError,
                      QStringLiteral("cannot list keys: %1.").arg(error));
    }

    return Result();
}

struct GPGmeKeyDelete
{
    QByteArray id;
    bool selected;
    bool done;
    GPGmeKeyDelete(GPGmeKey &primary, const QString &secretName)
        : selected(false), done(false)
    {
        int i = 0;
        while (primary.sub && secretName.compare(primary.fingerprint())) {
            i += 1;
            primary.sub = primary.sub->next;
        }
        id = QByteArray::number(i);
    }
    void setSelected()
    {
        selected = true;
    }
    bool isSelected() const
    {
        return selected;
    }
    void setDone()
    {
        done = true;
    }
    bool isDone() const
    {
        return done;
    }
    gpgme_error_t deleteKeyReply(gpgme_status_code_t status, const char *args, int fd)
    {
        QFile out;
        if (!out.open(fd, QIODevice::ReadWrite)) {
            qCWarning(lcSailfishCryptoPlugin) << "cannot edit:" << out.errorString();
            return GPG_ERR_GENERAL;
        }

        // Special arguments are taken from gnupg2/g10/keygen.c
#define PROMPT  QStringLiteral("keyedit.prompt")
#define CONFIRM QStringLiteral("keyedit.remove.subkey.okay")
#define SAVE    QStringLiteral("keyedit.save.okay")
        if (status == GPGME_STATUS_GET_LINE && PROMPT.compare(args) == 0
            && !isSelected()) {
            out.write("key " + id + "\n");
            setSelected();
            return GPG_ERR_NO_ERROR;
        } else if (status == GPGME_STATUS_GET_LINE && PROMPT.compare(args) == 0
                   && isSelected() && !isDone()) {
            out.write("delkey\n");
            return GPG_ERR_NO_ERROR;
        } else if (status == GPGME_STATUS_GET_BOOL && CONFIRM.compare(args) == 0) {
            out.write("y\n");
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

static gpgme_error_t _delete_cb(void *handle,
                                gpgme_status_code_t status, const char *args, int fd)
{
    GPGmeKeyDelete *params = static_cast<GPGmeKeyDelete*>(handle);
    qDebug() << status << args;
    return params->deleteKeyReply(status, args, fd);
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

    GPGmeKey primary = GPGmeKey::fromUid(ctx, collectionName);
    if (!primary) {
        return Result(Result::DatabaseError,
                      QStringLiteral("cannot list keys from %1: %2.").arg(collectionName).arg(primary.error()));
    }

    if (primary.fingerprint() == secretName || secretName.isEmpty()) {
        gpgme_error_t err;
#define DELETE_SECRET 1
        err = gpgme_op_delete(ctx, primary, DELETE_SECRET);
        if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
            return Result(Result::DatabaseError,
                          QStringLiteral("cannot delete key %1: %2.").arg(secretName).arg(gpgme_strerror(err)));
        }
    } else {
        GPGmeKeyDelete params(primary, secretName);
        GPGmeData out;
        gpgme_error_t err;
        err = gpgme_op_edit(ctx, primary, _delete_cb, &params, out);
        if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
            return Result(Result::DatabaseError,
                          QStringLiteral("cannot delete subkey %1: %2").arg(secretName).arg(gpgme_strerror(err)));
        }
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
