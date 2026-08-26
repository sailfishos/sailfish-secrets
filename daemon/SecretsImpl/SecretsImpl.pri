INCLUDEPATH += $$PWD
DEPENDPATH = $$INCLUDEPATH

include($$PWD/../../database/database.pri)

HEADERS += \
    $$PWD/metadatadb_p.h \
    $$PWD/pluginfunctionwrappers_p.h \
    $$PWD/pluginwrapper_p.h \
    $$PWD/secrets_p.h \
    $$PWD/secretsrequestprocessor_p.h \
    $$PWD/applicationpermissions_p.h \
    $$PWD/appsupportkeystore_p.h \
    $$PWD/appsupportkeystoreserver_p.h \
    $$PWD/dataprotector_p.h \
    $$PWD/devicelockbrokerclient_p.h \
    $$PWD/keymintdevicelocknotifier_p.h \
    $$PWD/masterkeymanager_p.h \
    $$PWD/masterkeycontroller_p.h

SOURCES += \
    $$PWD/metadatadb.cpp \
    $$PWD/pluginfunctionwrappers.cpp \
    $$PWD/pluginwrapper.cpp \
    $$PWD/secrets.cpp \
    $$PWD/secretsrequestprocessor.cpp \
    $$PWD/applicationpermissions.cpp \
    $$PWD/appsupportkeystore.cpp \
    $$PWD/appsupportkeystoreserver.cpp \
    $$PWD/dataprotector.cpp \
    $$PWD/devicelockbrokerclient.cpp \
    $$PWD/keymintdevicelocknotifier.cpp \
    $$PWD/masterkeymanager.cpp \
    $$PWD/masterkeycontroller.cpp

SOURCES += \
    $$PWD/secretscryptohelpers.cpp
