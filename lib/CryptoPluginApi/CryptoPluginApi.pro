TEMPLATE = lib
TARGET = sailfishcryptopluginapi
TARGET = $$qtLibraryTarget($$TARGET)
target.path = $$[QT_INSTALL_LIBS]
CONFIG += qt create_pc create_prl no_install_prl hide_symbols
DEFINES += SAILFISH_CRYPTO_LIBRARY_BUILD
QT -= gui

include($$PWD/../../common.pri)
include($$PWD/../libsailfishsecretspluginapi.pri)

INCLUDEPATH += $$PWD/../
DEPENDPATH += $$INCLUDEPATH $$PWD

HEADERS += \
    $$PWD/extensionplugins.h 

SOURCES += \
    $$PWD/extensionplugins.cpp \

develheaders.path = /usr/include/Sailfish/
develheaders_crypto.path = /usr/include/Sailfish/Crypto/
develheaders_crypto.files = $$HEADERS

pkgconfig.files = $$TARGET.pc
pkgconfig.path = $$target.path/pkgconfig

QMAKE_PKGCONFIG_NAME = lib$$TARGET
QMAKE_PKGCONFIG_LIBDIR = $$target.path
QMAKE_PKGCONFIG_INCDIR = $$develheaders.path $$develheaders_crypto.path
QMAKE_PKGCONFIG_VERSION = $$VERSION
QMAKE_PKGCONFIG_DESCRIPTION = Sailfish OS Crypto Plugin API
QMAKE_PKGCONFIG_DESTDIR = pkgconfig
QMAKE_PKGCONFIG_REQUIRES = Qt5Core sailfishcrypto sailfishsecretspluginapi

INSTALLS += target pkgconfig
INSTALLS += develheaders_crypto
