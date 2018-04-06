TEMPLATE = lib
TARGET = sailfishsecretspluginapi
TARGET = $$qtLibraryTarget($$TARGET)
target.path = $$[QT_INSTALL_LIBS]
CONFIG += qt create_pc create_prl no_install_prl hide_symbols
DEFINES += SAILFISH_SECRETS_LIBRARY_BUILD
QT -= gui

include($$PWD/../../common.pri)
include($$PWD/../libsailfishsecrets.pri)

INCLUDEPATH += $$PWD/../
DEPENDPATH += $$INCLUDEPATH $$PWD

HEADERS += \
    $$PWD/extensionplugins.h

SOURCES += \
    $$PWD/extensionplugins.cpp

develheaders.path = /usr/include/Sailfish/
develheaders_secrets.path = /usr/include/Sailfish/Secrets/
develheaders_secrets.files = $$HEADERS

pkgconfig.files = $$TARGET.pc
pkgconfig.path = $$target.path/pkgconfig

QMAKE_PKGCONFIG_NAME = lib$$TARGET
QMAKE_PKGCONFIG_LIBDIR = $$target.path
QMAKE_PKGCONFIG_INCDIR = $$develheaders.path $$develheaders_secrets.path
QMAKE_PKGCONFIG_VERSION = $$VERSION
QMAKE_PKGCONFIG_DESCRIPTION = Sailfish OS Secrets Plugin API
QMAKE_PKGCONFIG_DESTDIR = pkgconfig
QMAKE_PKGCONFIG_REQUIRES = Qt5Core sailfishsecrets

INSTALLS += target pkgconfig
INSTALLS += develheaders_secrets
