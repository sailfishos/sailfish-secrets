INCLUDEPATH += $$PWD
DEPENDPATH = $$INCLUDEPATH
PKGCONFIG += libcrypto

include($$PWD/../../database/database.pri)

HEADERS += \
    $$PWD/secrets_p.h \
    $$PWD/secretsrequestprocessor_p.h \
    $$PWD/secretsdatabase_p.h \
    $$PWD/applicationpermissions_p.h

SOURCES += \
    $$PWD/secrets.cpp \
    $$PWD/secretsrequestprocessor.cpp \
    $$PWD/applicationpermissions.cpp

SOURCES += \
    $$PWD/secretscryptohelpers.cpp

