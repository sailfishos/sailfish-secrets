TEMPLATE = lib
TARGET = sailfishcrypto
TARGET = $$qtLibraryTarget($$TARGET)
target.path = $$[QT_INSTALL_LIBS]
CONFIG += qt create_pc create_prl no_install_prl
DEFINES += SAILFISH_CRYPTO_LIBRARY_BUILD
QT += dbus
QT -= gui

include($$PWD/../../common.pri)

INCLUDEPATH += $$PWD/../
DEPENDPATH += $$INCLUDEPATH $$PWD

PUBLIC_HEADERS += \
    $$PWD/certificate.h \
    $$PWD/cryptodaemonconnection.h \
    $$PWD/cryptoglobal.h \
    $$PWD/cryptomanager.h \
    $$PWD/extensionplugins.h \
    $$PWD/key.h \
    $$PWD/result.h \
    $$PWD/x509certificate.h

PRIVATE_HEADERS += \
    $$PWD/certificate_p.h \
    $$PWD/cryptodaemonconnection_p.h \
    $$PWD/cryptomanager_p.h \
    $$PWD/extensionplugins_p.h \
    $$PWD/key_p.h

HEADERS += \
    $$PUBLIC_HEADERS \
    $$PRIVATE_HEADERS

SOURCES += \
    $$PWD/certificate.cpp \
    $$PWD/cryptodaemonconnection.cpp \
    $$PWD/cryptomanager.cpp \
    $$PWD/extensionplugins.cpp \
    $$PWD/key.cpp \
    $$PWD/serialisation.cpp \
    $$PWD/x509certificate.cpp

develheaders.path = /usr/include/Sailfish/
develheaders_crypto.path = /usr/include/Sailfish/Crypto/
develheaders_crypto.files = $$PUBLIC_HEADERS

pkgconfig.files = $$TARGET.pc
pkgconfig.path = $$target.path/pkgconfig

QMAKE_PKGCONFIG_NAME = lib$$TARGET
QMAKE_PKGCONFIG_LIBDIR = $$target.path
QMAKE_PKGCONFIG_INCDIR = $$develheaders.path $$develheaders_crypto.path
QMAKE_PKGCONFIG_VERSION = $$VERSION
QMAKE_PKGCONFIG_DESCRIPTION = Sailfish OS Crypto API
QMAKE_PKGCONFIG_DESTDIR = pkgconfig
QMAKE_PKGCONFIG_REQUIRES = QtDBus

INSTALLS += target pkgconfig
INSTALLS += develheaders_crypto
