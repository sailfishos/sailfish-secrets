TEMPLATE = lib
CONFIG += plugin
TARGET = sailfishcrypto-testopenssl
TARGET = $$qtLibraryTarget($$TARGET)

include($$PWD/../../../common.pri)
include($$PWD/../../../api/libsailfishcrypto/libsailfishcrypto.pri)

DEFINES += SAILFISH_CRYPTO_BUILD_TEST_PLUGIN
HEADERS += $$PWD/../../opensslcryptoplugin/evp_p.h $$PWD/../../opensslcryptoplugin/opensslcryptoplugin.h
SOURCES += $$PWD/../../opensslcryptoplugin/opensslcryptoplugin.cpp
OTHER_FILES += $$PWD/../../opensslcryptoplugin/cryptoplugin_common.cpp

target.path=/usr/lib/sailfishcrypto/
INSTALLS += target
