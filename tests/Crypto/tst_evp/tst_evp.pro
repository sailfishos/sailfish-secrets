TEMPLATE = app
TARGET = tst_evp
target.path = /opt/tests/Sailfish/Crypto/

QT += testlib
CONFIG += link_pkgconfig
PKGCONFIG += openssl

INCLUDEPATH += $$PWD/../../../plugins/opensslcryptoplugin/evp
DEPENDPATH  += $$PWD/../../../plugins/opensslcryptoplugin/evp

HEADERS += \
    $$PWD/../../../plugins/opensslcryptoplugin/evp/evp_p.h \
    tst_evp.h

SOURCES += \
    $$PWD/../../../plugins/opensslcryptoplugin/evp/evp.c \
    tst_evp.cpp

INSTALLS += target
