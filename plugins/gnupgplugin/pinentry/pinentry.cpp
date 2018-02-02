/*
 * Copyright (C) 2016 Caliste Damien.
 * Contact: Damien Caliste <dcaliste@free.fr>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include <QCoreApplication>
#include "qassuanserver.h"

class Pinentry : public QCoreApplication
{
public:
    Pinentry(int argc, char **argv)
        : QCoreApplication(argc, argv) {setApplicationName(QStringLiteral("pinentry"));};
    ~Pinentry() {};
public slots:
    void onStop()
    {
        exit(0);
    }
};

int main(int argc, char **argv)
{
    Pinentry pin(argc, argv);
    QAssuanServer server;

    pin.connect(&server, &QAssuanServer::finished, &pin, &Pinentry::onStop);
    server.start();

    return pin.exec();
}
