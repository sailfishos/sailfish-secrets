TEMPLATE = lib
CONFIG += plugin
TARGET = sailfishcrypto-openssl
TARGET = $$qtLibraryTarget($$TARGET)

include($$PWD/../../common.pri)
include($$PWD/../../lib/crypto/libsailfishcrypto.pri)

HEADERS += $$PWD/evp_p.h $$PWD/opensslcryptoplugin.h
SOURCES += $$PWD/opensslcryptoplugin.cpp
OTHER_FILES += $$PWD/cryptoplugin_common.cpp

target.path=/usr/lib/sailfish/crypto/
INSTALLS += target
