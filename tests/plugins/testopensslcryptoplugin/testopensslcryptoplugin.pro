TEMPLATE = lib
CONFIG += plugin
TARGET = sailfishcrypto-testopenssl
TARGET = $$qtLibraryTarget($$TARGET)

include($$PWD/../../../common.pri)
include($$PWD/../../../lib/libsailfishcrypto.pri)

DEFINES += SAILFISHCRYPTO_TESTPLUGIN

HEADERS += \
    $$PWD/../../../plugins/opensslcryptoplugin/evp_p.h \
    $$PWD/../../../plugins/opensslcryptoplugin/opensslcryptoplugin.h

SOURCES += \
    $$PWD/../../../plugins/opensslcryptoplugin/opensslcryptoplugin.cpp

OTHER_FILES += \
    $$PWD/../../../plugins/opensslcryptoplugin/cryptoplugin_common.cpp

target.path=/usr/lib/Sailfish/Crypto/
INSTALLS += target
