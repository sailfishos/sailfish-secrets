TEMPLATE = lib
CONFIG += plugin hide_symbols link_pkgconfig
TARGET = sailfishcrypto-keymint
TARGET = $$qtLibraryTarget($$TARGET)

include($$PWD/../../common.pri)
include($$PWD/../../lib/libsailfishcryptopluginapi.pri)

HEADERS += $$PWD/keymintcryptoplugin.h
SOURCES += $$PWD/keymintcryptoplugin.cpp

target.path=$$[QT_INSTALL_LIBS]/Sailfish/Crypto/
INSTALLS += target
