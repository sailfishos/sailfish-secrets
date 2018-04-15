TEMPLATE = lib
TARGET = sailfishcrypto
TARGET = $$qtLibraryTarget($$TARGET)
target.path = $$[QT_INSTALL_LIBS]
CONFIG += qt create_pc create_prl no_install_prl hide_symbols
DEFINES += SAILFISH_CRYPTO_LIBRARY_BUILD
QT += dbus
QT -= gui

include($$PWD/../../common.pri)

INCLUDEPATH += $$PWD/../
DEPENDPATH += $$INCLUDEPATH $$PWD

PUBLIC_HEADERS += \
    $$PWD/calculatedigestrequest.h \
    $$PWD/cipherrequest.h \
    $$PWD/cryptoglobal.h \
    $$PWD/cryptomanager.h \
    $$PWD/decryptrequest.h \
    $$PWD/deletestoredkeyrequest.h \
    $$PWD/encryptrequest.h \
    $$PWD/generateinitializationvectorrequest.h \
    $$PWD/generatekeyrequest.h \
    $$PWD/generaterandomdatarequest.h \
    $$PWD/generatestoredkeyrequest.h \
    $$PWD/importkeyrequest.h \
    $$PWD/importstoredkeyrequest.h \
    $$PWD/interactionparameters.h \
    $$PWD/key.h \
    $$PWD/keyderivationparameters.h \
    $$PWD/keypairgenerationparameters.h \
    $$PWD/lockcoderequest.h \
    $$PWD/plugininfo.h \
    $$PWD/plugininforequest.h \
    $$PWD/request.h \
    $$PWD/result.h \
    $$PWD/seedrandomdatageneratorrequest.h \
    $$PWD/signrequest.h \
    $$PWD/storedkeyidentifiersrequest.h \
    $$PWD/storedkeyrequest.h \
    $$PWD/verifyrequest.h

INTERNAL_PUBLIC_HEADERS += \
    $$PWD/cryptodaemonconnection_p.h \
    $$PWD/serialisation_p.h

PRIVATE_HEADERS += \
    $$PWD/calculatedigestrequest_p.h \
    $$PWD/cipherrequest_p.h \
    $$PWD/cryptodaemonconnection_p_p.h \
    $$PWD/cryptomanager_p.h \
    $$PWD/decryptrequest_p.h \
    $$PWD/deletestoredkeyrequest_p.h \
    $$PWD/encryptrequest_p.h \
    $$PWD/generateinitializationvectorrequest_p.h \
    $$PWD/generatekeyrequest_p.h \
    $$PWD/generaterandomdatarequest_p.h \
    $$PWD/generatestoredkeyrequest_p.h \
    $$PWD/importkeyrequest_p.h \
    $$PWD/importstoredkeyrequest_p.h \
    $$PWD/interactionparameters_p.h \
    $$PWD/key_p.h \
    $$PWD/keyderivationparameters_p.h \
    $$PWD/keypairgenerationparameters_p.h \
    $$PWD/lockcoderequest_p.h \
    $$PWD/plugininfo_p.h \
    $$PWD/plugininforequest_p.h \
    $$PWD/result_p.h \
    $$PWD/seedrandomdatageneratorrequest_p.h \
    $$PWD/signrequest_p.h \
    $$PWD/storedkeyidentifiersrequest_p.h \
    $$PWD/storedkeyrequest_p.h \
    $$PWD/verifyrequest_p.h

HEADERS += \
    $$PUBLIC_HEADERS \
    $$INTERNAL_PUBLIC_HEADERS \
    $$PRIVATE_HEADERS

SOURCES += \
    $$PWD/calculatedigestrequest.cpp \
    $$PWD/cipherrequest.cpp \
    $$PWD/cryptodaemonconnection.cpp \
    $$PWD/cryptomanager.cpp \
    $$PWD/decryptrequest.cpp \
    $$PWD/deletestoredkeyrequest.cpp \
    $$PWD/encryptrequest.cpp \
    $$PWD/generateinitializationvectorrequest.cpp \
    $$PWD/generatekeyrequest.cpp \
    $$PWD/generaterandomdatarequest.cpp \
    $$PWD/generatestoredkeyrequest.cpp \
    $$PWD/importkeyrequest.cpp \
    $$PWD/importstoredkeyrequest.cpp \
    $$PWD/interactionparameters.cpp \
    $$PWD/key.cpp \
    $$PWD/keyderivationparameters.cpp \
    $$PWD/keypairgenerationparameters.cpp \
    $$PWD/lockcoderequest.cpp \
    $$PWD/plugininfo.cpp \
    $$PWD/plugininforequest.cpp \
    $$PWD/request.cpp \
    $$PWD/result.cpp \
    $$PWD/seedrandomdatageneratorrequest.cpp \
    $$PWD/serialisation.cpp \
    $$PWD/signrequest.cpp \
    $$PWD/storedkeyidentifiersrequest.cpp \
    $$PWD/storedkeyrequest.cpp \
    $$PWD/verifyrequest.cpp

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
