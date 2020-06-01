TEMPLATE = lib
CONFIG += plugin hide_symbols link_pkgconfig
TARGET = sailfishcrypto-testopenpgp
TARGET = $$qtLibraryTarget($$TARGET)
LIBS += $$system(gpgme-config --libs)
PKGCONFIG += libcrypto

include($$PWD/../../../common.pri)
include($$PWD/../../../lib/libsailfishcrypto.pri)
INCLUDEPATH += $$PWD/../../../plugins/gnupgplugin

DEFINES += SAILFISHCRYPTO_TESTPLUGIN

HEADERS += $$PWD/../../../plugins/gnupgplugin/openpgpplugin/plugin.h \
           $$PWD/../../../plugins/gnupgplugin/gpgmebase.h \
           $$PWD/../../../plugins/gnupgplugin/gpgmestorage.h \
           $$PWD/../../../plugins/gnupgplugin/gpgme_p.h
SOURCES += $$PWD/../../../plugins/gnupgplugin/openpgpplugin/plugin.cpp \
           $$PWD/../../../plugins/gnupgplugin/gpgmebase.cpp \
           $$PWD/../../../plugins/gnupgplugin/gpgmestorage.cpp

target.path=$$[QT_INSTALL_LIBS]/Sailfish/Crypto/
INSTALLS += target
