/*
 * Copyright (C) 2016 Caliste Damien.
 * Contact: Damien Caliste <dcaliste@free.fr>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef QASSUANSERVER_H
#define QASSUANSERVER_H

#include <QThread>
#include <QMutex>
#include <QDebug>

#include <assuan.h>
#include <gpg-error.h>

#include <Secrets/secretmanager.h>
#include <Secrets/secret.h>
#include <Secrets/result.h>
#include <Secrets/interactionparameters.h>

#include <MGConfItem>

class QAssuanServer: public QThread
{
    Q_OBJECT

 public:
    QAssuanServer(QObject *parent = 0);
    ~QAssuanServer();

    void start();

 private:
    static const QString Temporary;

    friend gpg_error_t _assuan_cmd_confirm(assuan_context_t, char *);
    friend gpg_error_t _assuan_cmd_getpassphrase(assuan_context_t, char *);
    friend gpg_error_t _assuan_cmd_setdesc(assuan_context_t, char *);
    friend gpg_error_t _assuan_cmd_setkeyinfo(assuan_context_t, char *);
    friend gpg_error_t _assuan_cmd_setprompt(assuan_context_t, char *);
    friend gpg_error_t _assuan_cmd_seterror(assuan_context_t, char *);
    friend gpg_error_t _assuan_cmd_setrepeat(assuan_context_t, char *);
    friend gpg_error_t _assuan_cmd_setok(assuan_context_t, char *);
    friend gpg_error_t _assuan_cmd_setcancel(assuan_context_t, char *);
    friend gpg_error_t _assuan_cmd_stop(assuan_context_t, char *);
    friend gpg_error_t _option_handler(assuan_context_t, const char *, const char *);
    friend void _reset_handler(assuan_context_t);

    Sailfish::Secrets::SecretManager secretManager;
    Sailfish::Secrets::Secret::Identifier cacheId;
    Sailfish::Secrets::InteractionParameters::PromptText prompt;
    MGConfItem *m_useCache;

    bool m_connected;
    assuan_context_t m_ctx;
    bool m_request_stop;

    QString m_ctype;
    QString m_messages;

    void run();

    bool ensureCacheCollection();
    Sailfish::Secrets::Result requestConfirmation();
    Sailfish::Secrets::Result requestPassphrase(QByteArray *passphrase);
};

#endif
