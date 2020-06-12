TEMPLATE = lib
CONFIG += qt plugin hide_symbols link_pkgconfig c++11
TARGET = sailfishcrypto-examplecryptoplugin
TARGET = $$qtLibraryTarget($$TARGET)
PKGCONFIG += sailfishcryptopluginapi

HEADERS += \
    $$PWD/plugin.h

SOURCES += \
    $$PWD/plugin.cpp \
    $$PWD/cryptoplugin.cpp

OTHER_FILES += $$PWD/rpm/examplecryptoplugin.spec

target.path=$$[QT_INSTALL_LIBS]/Sailfish/Crypto/
INSTALLS += target
