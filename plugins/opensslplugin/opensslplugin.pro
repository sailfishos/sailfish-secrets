TEMPLATE = lib
CONFIG += plugin hide_symbols
TARGET = sailfishsecrets-openssl
TARGET = $$qtLibraryTarget($$TARGET)

include($$PWD/../../common.pri)
include($$PWD/../../lib/libsailfishsecrets.pri)

INCLUDEPATH += $$PWD/../opensslcryptoplugin/evp/
DEPENDPATH += $$PWD/../opensslcryptoplugin/evp/

HEADERS += \
    $$PWD/../opensslcryptoplugin/evp/evp_p.h \
    $$PWD/plugin.h
SOURCES += \
    $$PWD/../opensslcryptoplugin/evp/evp.c \
    $$PWD/plugin.cpp

target.path=/usr/lib/Sailfish/Secrets/
INSTALLS += target
