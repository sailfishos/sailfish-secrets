INCLUDEPATH += $$PWD
DEPENDPATH = $$INCLUDEPATH
PKGCONFIG += libcrypto

include($$PWD/../../database/database.pri)

HEADERS += \
    $$PWD/bookkeepingdatabase_p.h \
    $$PWD/secrets_p.h \
    $$PWD/secretsrequestprocessor_p.h \
    $$PWD/applicationpermissions_p.h

SOURCES += \
    $$PWD/bookkeepingdatabase.cpp \
    $$PWD/secrets.cpp \
    $$PWD/secretsrequestprocessor.cpp \
    $$PWD/applicationpermissions.cpp

SOURCES += \
    $$PWD/secretscryptohelpers.cpp

