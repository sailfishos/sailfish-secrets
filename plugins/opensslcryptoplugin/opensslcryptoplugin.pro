TEMPLATE = lib
CONFIG += plugin hide_symbols
TARGET = sailfishcrypto-openssl
TARGET = $$qtLibraryTarget($$TARGET)
DEFINES += SAILFISHCRYPTO_BUILD_OPENSSLCRYPTOPLUGIN

include($$PWD/../../common.pri)
include($$PWD/../../lib/libsailfishcrypto.pri)

INCLUDEPATH += $$PWD/evp/
DEPENDPATH += $$PWD/evp/
HEADERS += $$PWD/evp/evp_p.h $$PWD/evp/evp_helpers_p.h $$PWD/opensslcryptoplugin.h
SOURCES += $$PWD/evp/evp.c $$PWD/opensslcryptoplugin.cpp

target.path=/usr/lib/Sailfish/Crypto/
INSTALLS += target
