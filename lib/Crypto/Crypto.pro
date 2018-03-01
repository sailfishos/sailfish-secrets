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
    $$PWD/cipherrequest.h \
    $$PWD/cryptoglobal.h \
    $$PWD/cryptomanager.h \
    $$PWD/decryptrequest.h \
    $$PWD/deletestoredkeyrequest.h \
    $$PWD/encryptrequest.h \
    $$PWD/extensionplugins.h \
    $$PWD/generatekeyrequest.h \
    $$PWD/generaterandomdatarequest.h \
    $$PWD/generatestoredkeyrequest.h \
    $$PWD/interactionparameters.h \
    $$PWD/key.h \
    $$PWD/keyderivationparameters.h \
    $$PWD/keypairgenerationparameters.h \
    $$PWD/plugininforequest.h \
    $$PWD/request.h \
    $$PWD/result.h \
    $$PWD/seedrandomdatageneratorrequest.h \
    $$PWD/signrequest.h \
    $$PWD/storedkeyidentifiersrequest.h \
    $$PWD/storedkeyrequest.h \
    $$PWD/validatecertificatechainrequest.h \
    $$PWD/verifyrequest.h \
    $$PWD/x509certificate.h

INTERNAL_PUBLIC_HEADERS += \
    $$PWD/cryptodaemonconnection_p.h \
    $$PWD/serialisation_p.h

PRIVATE_HEADERS += \
    $$PWD/certificate_p.h \
    $$PWD/cipherrequest_p.h \
    $$PWD/cryptodaemonconnection_p_p.h \
    $$PWD/cryptomanager_p.h \
    $$PWD/decryptrequest_p.h \
    $$PWD/deletestoredkeyrequest_p.h \
    $$PWD/encryptrequest_p.h \
    $$PWD/extensionplugins_p.h \
    $$PWD/generatekeyrequest_p.h \
    $$PWD/generaterandomdatarequest_p.h \
    $$PWD/generatestoredkeyrequest_p.h \
    $$PWD/interactionparameters_p.h \
    $$PWD/key_p.h \
    $$PWD/keyderivationparameters_p.h \
    $$PWD/keypairgenerationparameters_p.h \
    $$PWD/plugininforequest_p.h \
    $$PWD/seedrandomdatageneratorrequest_p.h \
    $$PWD/signrequest_p.h \
    $$PWD/storedkeyidentifiersrequest_p.h \
    $$PWD/storedkeyrequest_p.h \
    $$PWD/validatecertificatechainrequest_p.h \
    $$PWD/verifyrequest_p.h

HEADERS += \
    $$PUBLIC_HEADERS \
    $$INTERNAL_PUBLIC_HEADERS \
    $$PRIVATE_HEADERS

SOURCES += \
    $$PWD/certificate.cpp \
    $$PWD/cipherrequest.cpp \
    $$PWD/cryptodaemonconnection.cpp \
    $$PWD/cryptomanager.cpp \
    $$PWD/decryptrequest.cpp \
    $$PWD/deletestoredkeyrequest.cpp \
    $$PWD/encryptrequest.cpp \
    $$PWD/extensionplugins.cpp \
    $$PWD/generatekeyrequest.cpp \
    $$PWD/generaterandomdatarequest.cpp \
    $$PWD/generatestoredkeyrequest.cpp \
    $$PWD/interactionparameters.cpp \
    $$PWD/key.cpp \
    $$PWD/keyderivationparameters.cpp \
    $$PWD/keypairgenerationparameters.cpp \
    $$PWD/plugininforequest.cpp \
    $$PWD/request.cpp \
    $$PWD/seedrandomdatageneratorrequest.cpp \
    $$PWD/serialisation.cpp \
    $$PWD/signrequest.cpp \
    $$PWD/storedkeyidentifiersrequest.cpp \
    $$PWD/storedkeyrequest.cpp \
    $$PWD/validatecertificatechainrequest.cpp \
    $$PWD/verifyrequest.cpp \
    $$PWD/x509certificate.cpp

develheaders.path = /usr/include/Sailfish/
develheaders_crypto.path = /usr/include/Sailfish/Crypto/
develheaders_crypto.files = $$PUBLIC_HEADERS $$INTERNAL_PUBLIC_HEADERS

pkgconfig.files = $$TARGET.pc
pkgconfig.path = $$target.path/pkgconfig

QMAKE_PKGCONFIG_NAME = lib$$TARGET
QMAKE_PKGCONFIG_LIBDIR = $$target.path
QMAKE_PKGCONFIG_INCDIR = $$develheaders.path $$develheaders_crypto.path
QMAKE_PKGCONFIG_VERSION = $$VERSION
QMAKE_PKGCONFIG_DESCRIPTION = Sailfish OS Crypto API
QMAKE_PKGCONFIG_DESTDIR = pkgconfig
QMAKE_PKGCONFIG_REQUIRES = Qt5Core Qt5DBus

INSTALLS += target pkgconfig
INSTALLS += develheaders_crypto
