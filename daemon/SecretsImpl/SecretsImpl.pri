INCLUDEPATH += $$PWD
DEPENDPATH = $$INCLUDEPATH

include($$PWD/../../database/database.pri)

HEADERS += \
    $$PWD/metadatadb_p.h \
    $$PWD/pluginfunctionwrappers_p.h \
    $$PWD/pluginwrapper_p.h \
    $$PWD/secrets_p.h \
    $$PWD/secretsrequestprocessor_p.h \
    $$PWD/applicationpermissions_p.h

SOURCES += \
    $$PWD/metadatadb.cpp \
    $$PWD/pluginfunctionwrappers.cpp \
    $$PWD/pluginwrapper.cpp \
    $$PWD/secrets.cpp \
    $$PWD/secretsrequestprocessor.cpp \
    $$PWD/applicationpermissions.cpp

SOURCES += \
    $$PWD/secretscryptohelpers.cpp

