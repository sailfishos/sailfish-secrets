TEMPLATE = lib
CONFIG += plugin hide_symbols link_pkgconfig c++11
TARGET = sailfishcrypto-keymint
TARGET = $$qtLibraryTarget($$TARGET)

include($$PWD/../../common.pri)
include($$PWD/../../lib/libsailfishcryptopluginapi.pri)

PKGCONFIG += libgbinder libcrypto

HEADERS += \
    $$PWD/keymintbinderclient_p.h \
    $$PWD/keymintcryptoplugin.h

SOURCES += \
    $$PWD/keymintbinderclient.cpp \
    $$PWD/keymintcryptoplugin.cpp

target.path=$$[QT_INSTALL_LIBS]/Sailfish/Crypto/
INSTALLS += target
