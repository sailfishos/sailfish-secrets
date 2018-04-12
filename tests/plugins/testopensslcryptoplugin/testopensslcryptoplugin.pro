TEMPLATE = lib
CONFIG += plugin hide_symbols link_pkgconfig
TARGET = sailfishcrypto-testopenssl
TARGET = $$qtLibraryTarget($$TARGET)
PKGCONFIG += libcrypto

include($$PWD/../../../common.pri)
include($$PWD/../../../lib/libsailfishcrypto.pri)

DEFINES += SAILFISHCRYPTO_TESTPLUGIN SAILFISHCRYPTO_BUILD_OPENSSLCRYPTOPLUGIN

INCLUDEPATH += $$PWD/../../../plugins/opensslcryptoplugin/evp/
DEPENDPATH += $$PWD/../../../plugins/opensslcryptoplugin/evp/

HEADERS += \
    $$PWD/../../../plugins/opensslcryptoplugin/evp/evp_p.h \
    $$PWD/../../../plugins/opensslcryptoplugin/opensslcryptoplugin.h

SOURCES += \
    $$PWD/../../../plugins/opensslcryptoplugin/evp/evp.c \
    $$PWD/../../../plugins/opensslcryptoplugin/opensslcryptoplugin.cpp

target.path=/usr/lib/Sailfish/Crypto/
INSTALLS += target
