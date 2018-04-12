TEMPLATE = lib
CONFIG += plugin hide_symbols link_pkgconfig
TARGET = sailfishsecrets-testopenssl
TARGET = $$qtLibraryTarget($$TARGET)
PKGCONFIG += libcrypto

include($$PWD/../../../common.pri)
include($$PWD/../../../lib/libsailfishsecrets.pri)

DEFINES += SAILFISHSECRETS_TESTPLUGIN

INCLUDEPATH += $$PWD/../../../plugins/opensslcryptoplugin/evp/
DEPENDPATH += $$PWD/../../../plugins/opensslcryptoplugin/evp/

HEADERS += \
    $$PWD/../../../plugins/opensslcryptoplugin/evp/evp_p.h \
    $$PWD/../../../plugins/opensslplugin/plugin.h

SOURCES += \
    $$PWD/../../../plugins/opensslcryptoplugin/evp/evp.c \
    $$PWD/../../../plugins/opensslplugin/plugin.cpp

target.path=/usr/lib/Sailfish/Secrets/
INSTALLS += target
