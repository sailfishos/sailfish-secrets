TEMPLATE = lib
TARGET = sailfishsecrets
TARGET = $$qtLibraryTarget($$TARGET)
target.path = $$[QT_INSTALL_LIBS]
CONFIG += qt create_pc create_prl no_install_prl
DEFINES += SAILFISH_SECRETS_LIBRARY_BUILD
QT += dbus
QT -= gui

include($$PWD/../../common.pri)

INCLUDEPATH += $$PWD/../
DEPENDPATH += $$INCLUDEPATH $$PWD

PUBLIC_HEADERS += \
    $$PWD/createcollectionrequest.h \
    $$PWD/deletecollectionrequest.h \
    $$PWD/deletesecretrequest.h \
    $$PWD/extensionplugins.h \
    $$PWD/findsecretsrequest.h \
    $$PWD/request.h \
    $$PWD/result.h \
    $$PWD/secret.h \
    $$PWD/secretmanager.h \
    $$PWD/secretsglobal.h \
    $$PWD/storedsecretrequest.h \
    $$PWD/storesecretrequest.h \
    $$PWD/interactionparameters.h \
    $$PWD/interactionresponse.h \
    $$PWD/interactionrequestwatcher.h \
    $$PWD/interactionview.h

INTERNAL_PUBLIC_HEADERS += \
    $$PWD/secretsdaemonconnection_p.h \
    $$PWD/serialisation_p.h

PRIVATE_HEADERS += \
    $$PWD/createcollectionrequest_p.h \
    $$PWD/deletecollectionrequest_p.h \
    $$PWD/deletesecretrequest_p.h \
    $$PWD/findsecretsrequest_p.h \
    $$PWD/interactionparameters_p.h \
    $$PWD/interactionresponse_p.h \
    $$PWD/secretsdaemonconnection_p_p.h \
    $$PWD/secretmanager_p.h \
    $$PWD/storedsecretrequest_p.h \
    $$PWD/storesecretrequest_p.h \
    $$PWD/interactionservice_p.h

HEADERS += \
    $$PUBLIC_HEADERS \
    $$INTERNAL_PUBLIC_HEADERS \
    $$PRIVATE_HEADERS

SOURCES += \
    $$PWD/createcollectionrequest.cpp \
    $$PWD/deletecollectionrequest.cpp \
    $$PWD/deletesecretrequest.cpp \
    $$PWD/extensionplugins.cpp \
    $$PWD/findsecretsrequest.cpp \
    $$PWD/request.cpp \
    $$PWD/secretsdaemonconnection.cpp \
    $$PWD/secretmanager.cpp \
    $$PWD/serialisation.cpp \
    $$PWD/storedsecretrequest.cpp \
    $$PWD/storesecretrequest.cpp \
    $$PWD/interactionparameters.cpp \
    $$PWD/interactionresponse.cpp \
    $$PWD/interactionrequestwatcher.cpp \
    $$PWD/interactionservice.cpp

develheaders.path = /usr/include/Sailfish/
develheaders_secrets.path = /usr/include/Sailfish/Secrets/
develheaders_secrets.files = $$PUBLIC_HEADERS $$INTERNAL_PUBLIC_HEADERS

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
