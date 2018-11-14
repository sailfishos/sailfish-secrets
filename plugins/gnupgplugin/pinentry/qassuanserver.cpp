/*
 * Copyright (C) 2016 Caliste Damien.
 * Contact: Damien Caliste <dcaliste@free.fr>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "qassuanserver.h"

#include <Secrets/storesecretrequest.h>
#include <Secrets/storedsecretrequest.h>
#include <Secrets/interactionrequest.h>
#include <Secrets/createcollectionrequest.h>

#include <QtCore/QLoggingCategory>

Q_LOGGING_CATEGORY(lcSailfishPinentry, "org.sailfishos.secrets.gnupg.pinentry", QtWarningMsg)

const QString QAssuanServer::Temporary = QStringLiteral("Temporary");

// To be removed when upgrading libassuan to a modern version using gpg-error.
typedef int (*OptionHandler)(assuan_context_t, const char*, const char*);
typedef int (*CmdHandler)(assuan_context_t, char *);

void _reset_handler(assuan_context_t ctx)
{
    qCDebug(lcSailfishPinentry) << __func__;
    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));

    self->cacheId.setName(QString());
    self->prompt = Sailfish::Secrets::InteractionParameters::PromptText();
}

gpg_error_t _option_handler(assuan_context_t ctx, const char *key, const char *value)
{
    qCDebug(lcSailfishPinentry) << __func__ << key << value;
    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));

    if (!strcmp(key, "no-grab") && !*value) {
        return ASSUAN_Not_Implemented;
    } else if (!strcmp(key, "grab") && !*value) {
        return 0; // Silently ignore.
    } else if (!strcmp(key, "debug-wait")) {
        return ASSUAN_Not_Implemented;
    } else if (!strcmp(key, "display")) {
        return ASSUAN_Not_Implemented;
    } else if (!strcmp(key, "ttyname")) {
        return 0; // Silently ignore.
    } else if (!strcmp(key, "ttytype")) {
        return 0; // Silently ignore.
    } else if (!strcmp(key, "lc-ctype")) {
        self->m_ctype = value;
    } else if (!strcmp(key, "lc-messages")) {
        self->m_messages = value;
    } else if (!strcmp(key, "parent-wid")) {
        return ASSUAN_Not_Implemented;
    } else if (!strcmp(key, "touch-file")) {
        return ASSUAN_Not_Implemented;
    } else if (!strcmp(key, "default-ok")) {
        return ASSUAN_Not_Implemented;
    } else if (!strcmp(key, "default-cancel")) {
        return ASSUAN_Not_Implemented;
    } else if (!strcmp(key, "default-prompt")) {
        return ASSUAN_Not_Implemented;
    } else if (!strcmp(key, "default-pwmngr")) {
        return ASSUAN_Not_Implemented;
    } else if (!strcmp(key, "allow-external-password-cache") && !*value) {
        return ASSUAN_Not_Implemented;
    } else if (!strcmp(key, "invisible-char")) {
        return ASSUAN_Not_Implemented;
    } else
        return ASSUAN_Invalid_Option;
    return 0;
}

gpg_error_t _assuan_cmd_setdesc(assuan_context_t ctx, char *line)
{
    qCDebug(lcSailfishPinentry) << __func__ << line;
    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));
    self->prompt.setMessage(QByteArray::fromPercentEncoding(line));

    // Ugly hack here due to GnuPG being stuck in 2.0.4
    // and not having SETKEYINFO command yet. Description may contain "ID xxxxx".
    {
        const QString &str(self->prompt.message());
        int id = str.lastIndexOf("ID ");
        if (id > 0) {
            self->cacheId.setName(str.mid(id + 3, 8));
            qCDebug(lcSailfishPinentry) << "cacheID" << self->cacheId.name();
        }
    }
    return 0;
}

gpg_error_t _assuan_cmd_setprompt(assuan_context_t ctx, char *line)
{
    Q_UNUSED(ctx);
    qCDebug(lcSailfishPinentry) << __func__ << line;

    //QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));
    //self->m_prompt = QByteArray::fromPercentEncoding(line);
    return 0;
}

gpg_error_t _assuan_cmd_seterror(assuan_context_t ctx, char *line)
{
    qCDebug(lcSailfishPinentry) << __func__ << line;
    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));
    self->prompt.setInstruction(QByteArray::fromPercentEncoding(line));
    return 0;
}

gpg_error_t _assuan_cmd_setrepeat(assuan_context_t ctx, char *line)
{
    qCDebug(lcSailfishPinentry) << __func__ << line;
    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));
    self->cacheId.setName(QString());

    return 0;
}

gpg_error_t _assuan_cmd_setok(assuan_context_t ctx, char *line)
{
    qCDebug(lcSailfishPinentry) << __func__ << line;
    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));
    self->prompt.setAccept(QByteArray::fromPercentEncoding(line));

    return 0;
}

gpg_error_t _assuan_cmd_setcancel(assuan_context_t ctx, char *line)
{
    qCDebug(lcSailfishPinentry) << __func__ << line;
    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));
    self->prompt.setCancel(QByteArray::fromPercentEncoding(line));

    return 0;
}

/* The data provided at LINE may be used by pinentry implementations
   to identify a key for caching strategies of its own.  The empty
   string and --clear mean that the key does not have a stable
   identifier.  */
gpg_error_t _assuan_cmd_setkeyinfo(assuan_context_t ctx, char *line)
{
    qCDebug(lcSailfishPinentry) << __func__ << line;
    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));
    self->cacheId.setName((*line && strcmp(line, "--clear") !=0) ? line : QString());

    return 0;
}

gpg_error_t _assuan_cmd_getpassphrase(assuan_context_t ctx, char *line)
{
    qCDebug(lcSailfishPinentry) << __func__ << line;
    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));

    QByteArray passphrase;
    Sailfish::Secrets::Result result = self->requestPassphrase(&passphrase);
    if (result.errorCode() == Sailfish::Secrets::Result::InteractionViewUserCanceledError) {
        qCWarning(lcSailfishPinentry) << "cancelation" << result.errorMessage();
        return ASSUAN_Canceled;
    }
    if (result.code() != Sailfish::Secrets::Result::Succeeded) {
        qCWarning(lcSailfishPinentry) << result.errorMessage();
        return ASSUAN_General_Error;
    }

    if (self->cacheId.isValid()) {
        assuan_write_status(self->m_ctx, "PASSWORD_FROM_CACHE", "");
    }
    gpg_error_t rc = assuan_send_data(self->m_ctx, passphrase.constData(), passphrase.length());
    if (!rc) {
        rc = assuan_send_data(self->m_ctx, NULL, 0);
    }

    return rc;
}

gpg_error_t _assuan_cmd_confirm(assuan_context_t ctx, char *line)
{
    qCDebug(lcSailfishPinentry) << __func__ << line;
    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));

    Sailfish::Secrets::Result result = self->requestConfirmation();
    if (result.errorCode() == Sailfish::Secrets::Result::InteractionViewUserCanceledError) {
      return ASSUAN_Canceled;
    }
    if (result.code() != Sailfish::Secrets::Result::Succeeded) {
        qCWarning(lcSailfishPinentry) << result.errorMessage();
        return ASSUAN_General_Error;
    }
    return ASSUAN_No_Error;
}

#define PACKAGE_VERSION "0.0.1"
/* GETINFO <what>

   Multipurpose function to return a variety of information.
   Supported values for WHAT are:

     version     - Return the version of the program.
     pid         - Return the process id of the server.
 */
static gpg_error_t _assuan_cmd_getinfo(assuan_context_t ctx, char *line)
{
    qCDebug(lcSailfishPinentry) << __func__ << line;
    int rc = 0;
    if (!strcmp(line, "version")) {
        const char *s = PACKAGE_VERSION;
        rc = assuan_send_data (ctx, s, strlen (s));
    } else if (!strcmp(line, "pid")) {
        char numbuf[50];

        snprintf (numbuf, sizeof numbuf, "%lu", (unsigned long)getpid ());
        rc = assuan_send_data(ctx, numbuf, strlen (numbuf));
    } else {
        rc = ASSUAN_Parameter_Error;
    }
    return rc;
}

gpg_error_t _assuan_cmd_stop(assuan_context_t ctx, char *line)
{
    qCDebug(lcSailfishPinentry) << __func__ << line;
    // assuan_set_flag(ctx, ASSUAN_FORCE_CLOSE, 1);
    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));
    self->m_request_stop = true;

    return 0;
}

/* Tell the assuan library about our commands.  */
static gpg_error_t register_commands(assuan_context_t ctx)
{
  static struct
  {
    const char *name;
    int (*handler) (assuan_context_t, char *line);
  } table[] =
    {
      { "SETDESC",        (CmdHandler)_assuan_cmd_setdesc },
      { "SETPROMPT",      (CmdHandler)_assuan_cmd_setprompt },
      { "SETERROR",       (CmdHandler)_assuan_cmd_seterror },
      { "SETKEYINFO",     (CmdHandler)_assuan_cmd_setkeyinfo }, // Not yet present in 2.0.4
      { "SETREPEAT",      (CmdHandler)_assuan_cmd_setrepeat },  // Not yet present in 2.0.4
      { "SETOK",          (CmdHandler)_assuan_cmd_setok },
      { "SETCANCEL",      (CmdHandler)_assuan_cmd_setcancel },
      { "GETPIN",         (CmdHandler)_assuan_cmd_getpassphrase },
      { "CONFIRM",        (CmdHandler)_assuan_cmd_confirm },
      { "GETINFO",        (CmdHandler)_assuan_cmd_getinfo },
      { "STOP",           (CmdHandler)_assuan_cmd_stop },
      { NULL, NULL }
    };
  int i, j;
  gpg_error_t rc;

  for (i = j = 0; table[i].name; i++) {
      rc = assuan_register_command(ctx, table[i].name, table[i].handler);
      if (rc)
          return rc;
  }
  return 0;
}

QAssuanServer::QAssuanServer(QObject *parent)
    : QThread(parent)
    , secretManager()
    , m_useCache(new MGConfItem("/desktop/sailfish/secrets/storeGnuPGPassphrases", this))
    , m_connected(false)
    , m_request_stop(false)
{
    gpg_error_t rc;
    int filedesc[2];

    filedesc[0] = 0;
    filedesc[1] = 1;
    rc = assuan_init_pipe_server(&m_ctx, filedesc);
    if (rc) {
        qCWarning(lcSailfishPinentry) << "failed to initialize the server: " << gpg_strerror(rc);
        return;
    }
    m_connected = true;
    rc = register_commands(m_ctx);
    if (rc) {
        qCWarning(lcSailfishPinentry) << "failed to the register commands with Assuan: " << gpg_strerror(rc);
        assuan_deinit_server(m_ctx);
        return;
    }

    assuan_set_pointer(m_ctx, this);
    rc = assuan_register_option_handler(m_ctx, (OptionHandler)_option_handler);
    if (rc) {
        qCWarning(lcSailfishPinentry) << "failed to the register option handler with Assuan: " << gpg_strerror(rc);
        assuan_deinit_server(m_ctx);
        return;
    }
    rc = assuan_register_reset_notify(m_ctx, _reset_handler);
    if (rc) {
        qCWarning(lcSailfishPinentry) << "failed to the register reset handler with Assuan: " << gpg_strerror(rc);
        assuan_deinit_server(m_ctx);
        return;
    }

    cacheId.setCollectionName(QStringLiteral("GnuPG"));
    cacheId.setStoragePluginName(Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName);
}

QAssuanServer::~QAssuanServer()
{
    if (isRunning()) {
        terminate();
        wait(500);
    }
    if (m_connected) {
        assuan_deinit_server(m_ctx);
    }
}

void QAssuanServer::start()
{
    if (!m_connected) {
        return;
    }

    QThread::start();
}

void QAssuanServer::run()
{
    assuan_error_t rc;

    for (;;) {
        rc = assuan_accept(m_ctx);
        if (rc == -1)
            break;
        else if (rc) {
            qCWarning(lcSailfishPinentry) << "Assuan accept failed: " << assuan_strerror(rc);
            break;
        }

        rc = assuan_process(m_ctx);
        if (rc) {
            qCWarning(lcSailfishPinentry) << "Assuan processing failed: " << assuan_strerror(rc);
            continue;
        }

        if (m_request_stop) {
            break;
        }
    }
    qCDebug(lcSailfishPinentry) << "Assuan loop finished.";
}

Sailfish::Secrets::Result QAssuanServer::requestPassphrase(QByteArray *passphrase)
{
    passphrase->clear();

    bool useCache = m_useCache->value(QVariant(true)).toBool();
    if (useCache && cacheId.isValid()) {
        Sailfish::Secrets::StoredSecretRequest request;
        qCDebug(lcSailfishPinentry) << "Starting cache request for" << cacheId.name();
        request.setManager(&secretManager);
        request.setUserInteractionMode(Sailfish::Secrets::SecretManager::SystemInteraction);
        request.setIdentifier(cacheId);
        request.startRequest();
        request.waitForFinished();
        qCDebug(lcSailfishPinentry) << "-> return code" << request.result().code();
        qCDebug(lcSailfishPinentry) << request.result().errorMessage();
        if (request.result().code() == Sailfish::Secrets::Result::Succeeded) {
            qCDebug(lcSailfishPinentry) << "found cached secret";
            *passphrase = request.secret().data();
            return request.result();
        }
    }

    Sailfish::Secrets::InteractionParameters uiParams;
    uiParams.setPromptText(prompt);
    uiParams.setInputType(Sailfish::Secrets::InteractionParameters::AlphaNumericInput);
    uiParams.setEchoMode(Sailfish::Secrets::InteractionParameters::PasswordEcho);

    Sailfish::Secrets::InteractionRequest request;
    request.setInteractionParameters(uiParams);
    request.setManager(&secretManager);

    qCDebug(lcSailfishPinentry) << "Starting passphrase request";
    request.startRequest();
    request.waitForFinished();
    qCDebug(lcSailfishPinentry) << "-> return code" << request.result().code();
    if (request.result().code() == Sailfish::Secrets::Result::Succeeded) {
        *passphrase = request.userInput();
        if (useCache && cacheId.isValid() && ensureCacheCollection()) {
            Sailfish::Secrets::StoreSecretRequest store;
            // store.setInteractionParameters(uiParams);

            store.setManager(&secretManager);
            store.setSecretStorageType(Sailfish::Secrets::StoreSecretRequest::CollectionSecret);
            store.setUserInteractionMode(Sailfish::Secrets::SecretManager::SystemInteraction);

            Sailfish::Secrets::Secret pin(cacheId);
            pin.setType(Sailfish::Secrets::Secret::TypeBlob);
            pin.setData(request.userInput());
            store.setSecret(pin);

            qCDebug(lcSailfishPinentry) << "Storing passphrase for" << cacheId.name();
            store.startRequest();
            store.waitForFinished();
            qCDebug(lcSailfishPinentry) << "-> return code" << store.result().code();
            if (store.result().code() != Sailfish::Secrets::Result::Succeeded)
                qCWarning(lcSailfishPinentry) << store.result().errorMessage();
        }
    }

    return request.result();
}

Sailfish::Secrets::Result QAssuanServer::requestConfirmation()
{
    Sailfish::Secrets::InteractionParameters uiParams;
    uiParams.setPromptText(prompt);
    uiParams.setInputType(Sailfish::Secrets::InteractionParameters::ConfirmationInput);

    Sailfish::Secrets::InteractionRequest request;
    request.setInteractionParameters(uiParams);

    request.setManager(&secretManager);

    qCDebug(lcSailfishPinentry) << "Starting confirmation request";
    request.startRequest();
    request.waitForFinished();
    qCDebug(lcSailfishPinentry) << "-> return code" << request.result().code();
    return request.result();
}

bool QAssuanServer::ensureCacheCollection()
{
    // Ensure collection exists.
    Sailfish::Secrets::CreateCollectionRequest request;
    request.setManager(&secretManager);
    request.setCollectionName(cacheId.collectionName());
    request.setAccessControlMode(Sailfish::Secrets::SecretManager::OwnerOnlyMode);
    request.setCollectionLockType(Sailfish::Secrets::CreateCollectionRequest::DeviceLock);
    request.setDeviceLockUnlockSemantic(Sailfish::Secrets::SecretManager::DeviceLockKeepUnlocked);
    request.setStoragePluginName(Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName);
    request.setEncryptionPluginName(Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName);
    request.startRequest();
    request.waitForFinished();
    if (request.result().code() == Sailfish::Secrets::Result::Failed
        && request.result().errorCode() != Sailfish::Secrets::Result::CollectionAlreadyExistsError) {
        qCWarning(lcSailfishPinentry) << "Ensuring collection failed:" << request.result().errorMessage();
        return false;
    }
    return true;
}
