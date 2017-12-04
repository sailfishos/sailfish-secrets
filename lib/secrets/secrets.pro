TEMPLATE = lib
TARGET = sailfishsecrets
TARGET = $$qtLibraryTarget($$TARGET)
target.path = $$[QT_INSTALL_LIBS]
CONFIG += qt create_pc create_prl no_install_prl
DEFINES += SAILFISH_SECRETS_LIBRARY_BUILD
QT += dbus
QT -= gui

include($$PWD/../../common.pri)

INCLUDEPATH += $$PWD
DEPENDPATH = $$INCLUDEPATH

PUBLIC_HEADERS += \
    $$PWD/Secrets/extensionplugins.h \
    $$PWD/Secrets/result.h \
    $$PWD/Secrets/secret.h \
    $$PWD/Secrets/secretmanager.h \
    $$PWD/Secrets/secretsdaemonconnection.h \
    $$PWD/Secrets/secretsglobal.h \
    $$PWD/Secrets/interactionrequest.h \
    $$PWD/Secrets/interactionrequestwatcher.h \
    $$PWD/Secrets/interactionview.h

PRIVATE_HEADERS += \
    $$PWD/Secrets/secretsdaemonconnection_p.h \
    $$PWD/Secrets/secretmanager_p.h \
    $$PWD/Secrets/interactionservice_p.h

HEADERS += \
    $$PUBLIC_HEADERS \
    $$PRIVATE_HEADERS

SOURCES += \
    $$PWD/Secrets/extensionplugins.cpp \
    $$PWD/Secrets/secretsdaemonconnection.cpp \
    $$PWD/Secrets/secretmanager.cpp \
    $$PWD/Secrets/serialisation.cpp \
    $$PWD/Secrets/interactionrequestwatcher.cpp \
    $$PWD/Secrets/interactionservice.cpp

develheaders.path = /usr/include/libsailfishsecrets/
develheaders_secrets.path = /usr/include/libsailfishsecrets/Secrets/
develheaders_secrets.files = $$PUBLIC_HEADERS

pkgconfig.files = $$TARGET.pc
pkgconfig.path = $$target.path/pkgconfig

QMAKE_PKGCONFIG_NAME = lib$$TARGET
QMAKE_PKGCONFIG_LIBDIR = $$target.path
QMAKE_PKGCONFIG_INCDIR = $$develheaders.path $$develheaders_secrets.path
QMAKE_PKGCONFIG_VERSION = $$VERSION
QMAKE_PKGCONFIG_DESCRIPTION = Sailfish OS Secrets API
QMAKE_PKGCONFIG_DESTDIR = pkgconfig
QMAKE_PKGCONFIG_REQUIRES = QtDBus

INSTALLS += target pkgconfig
INSTALLS += develheaders_secrets
