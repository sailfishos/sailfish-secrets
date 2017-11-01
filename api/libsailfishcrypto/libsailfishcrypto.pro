TEMPLATE=lib
TARGET=sailfishcrypto
TARGET = $$qtLibraryTarget($$TARGET)
target.path = $$[QT_INSTALL_LIBS]
CONFIG += qt create_pc create_prl no_install_prl
DEFINES += SAILFISH_CRYPTO_LIBRARY_BUILD
QT += dbus
QT -= gui

include($$PWD/../../common.pri)

INCLUDEPATH += $$PWD
DEPENDPATH = $$INCLUDEPATH

PUBLIC_HEADERS += \
    $$PWD/Crypto/certificate.h \
    $$PWD/Crypto/cryptodaemonconnection.h \
    $$PWD/Crypto/cryptoglobal.h \
    $$PWD/Crypto/cryptomanager.h \
    $$PWD/Crypto/extensionplugins.h \
    $$PWD/Crypto/key.h \
    $$PWD/Crypto/result.h \
    $$PWD/Crypto/x509certificate.h

PRIVATE_HEADERS += \
    $$PWD/Crypto/certificate_p.h \
    $$PWD/Crypto/cryptodaemonconnection_p.h \
    $$PWD/Crypto/cryptomanager_p.h \
    $$PWD/Crypto/extensionplugins_p.h \
    $$PWD/Crypto/key_p.h

HEADERS += \
    $$PUBLIC_HEADERS \
    $$PRIVATE_HEADERS

SOURCES += \
    $$PWD/Crypto/certificate.cpp \
    $$PWD/Crypto/cryptodaemonconnection.cpp \
    $$PWD/Crypto/cryptomanager.cpp \
    $$PWD/Crypto/extensionplugins.cpp \
    $$PWD/Crypto/key.cpp \
    $$PWD/Crypto/serialisation.cpp \
    $$PWD/Crypto/x509certificate.cpp

develheaders.path = /usr/include/libsailfishcrypto/
develheaders_crypto.path = /usr/include/libsailfishcrypto/Crypto/
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
