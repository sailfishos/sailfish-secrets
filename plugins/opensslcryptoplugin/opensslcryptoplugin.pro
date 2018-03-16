TEMPLATE = lib
CONFIG += plugin hide_symbols
TARGET = sailfishcrypto-openssl
TARGET = $$qtLibraryTarget($$TARGET)

include($$PWD/../../common.pri)
include($$PWD/../../lib/libsailfishcrypto.pri)

INCLUDEPATH += $$PWD/evp/
DEPENDPATH += $$PWD/evp/
HEADERS += $$PWD/evp/evp_p.h $$PWD/opensslcryptoplugin.h
SOURCES += $$PWD/evp/evp.c $$PWD/opensslcryptoplugin.cpp
OTHER_FILES += $$PWD/cryptoplugin_common.cpp

target.path=/usr/lib/Sailfish/Crypto/
INSTALLS += target
