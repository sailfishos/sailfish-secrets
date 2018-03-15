TEMPLATE = app
TARGET = sailfishsecretsd

include($$PWD/../common.pri)
include($$PWD/../lib/libsailfishsecrets.pri)
include($$PWD/../lib/libsailfishcrypto.pri)

QT += sql dbus

CONFIG += link_pkgconfig hide_symbols
PKGCONFIG += dbus-1

HEADERS += \
    $$PWD/controller_p.h \
    $$PWD/discoveryobject_p.h \
    $$PWD/logging_p.h \
    $$PWD/plugin_p.h \
    $$PWD/requestqueue_p.h

SOURCES += \
    $$PWD/controller.cpp \
    $$PWD/plugin_p.cpp \
    $$PWD/requestqueue.cpp \
    $$PWD/main.cpp

include($$PWD/SecretsImpl/SecretsImpl.pri)
include($$PWD/CryptoImpl/CryptoImpl.pri)

target.path = /usr/bin/
INSTALLS += target
