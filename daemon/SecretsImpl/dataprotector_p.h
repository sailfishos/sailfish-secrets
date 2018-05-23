/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Timur Kristóf <timur.kristof@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_APIIMPL_DATAPROTECTOR_P_H
#define SAILFISHSECRETS_APIIMPL_DATAPROTECTOR_P_H

#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QByteArray>

namespace Sailfish {

namespace Secrets {

namespace Daemon {

namespace ApiImpl {

class DataProtector final : public QObject
{

    Q_OBJECT

public:
    enum Status
    {
        Success = 0,
        Irretrievable,
        ErrorGotNullptr,
        ErrorCannotCreateDirectory,
        ErrorCannotDeleteDirectory,
        ErrorCannotCreateFile,
        ErrorCannotOpenFile,
        ErrorCannotWriteFile,

    };
    Q_ENUM(Status)

    explicit DataProtector(const QString &path, QObject *parent = Q_NULLPTR);
    QString path() const;

    Q_INVOKABLE Status getData(QByteArray *output);
    Q_INVOKABLE Status putData(const QByteArray &bytes);

private:
    QString m_path;
    QByteArray m_data;

};

}

}

}

}

#endif // SAILFISHSECRETS_APIIMPL_DATAPROTECTOR_P_H
