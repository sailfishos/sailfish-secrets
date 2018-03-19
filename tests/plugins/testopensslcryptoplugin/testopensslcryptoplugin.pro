TEMPLATE = lib
CONFIG += plugin
TARGET = sailfishcrypto-testopenssl
TARGET = $$qtLibraryTarget($$TARGET)

include($$PWD/../../../common.pri)
include($$PWD/../../../lib/libsailfishcrypto.pri)

DEFINES += SAILFISHCRYPTO_TESTPLUGIN

INCLUDEPATH += $$PWD/../../../plugins/opensslcryptoplugin/evp/
DEPENDPATH += $$PWD/../../../plugins/opensslcryptoplugin/evp/

HEADERS += \
    $$PWD/../../../plugins/opensslcryptoplugin/evp/evp_p.h \
    $$PWD/../../../plugins/opensslcryptoplugin/opensslcryptoplugin.h

SOURCES += \
    $$PWD/../../../plugins/opensslcryptoplugin/evp/evp.c \
    $$PWD/../../../plugins/opensslcryptoplugin/opensslcryptoplugin.cpp

OTHER_FILES += \
    $$PWD/../../../plugins/opensslcryptoplugin/cryptoplugin_common.cpp

target.path=/usr/lib/Sailfish/Crypto/
INSTALLS += target
