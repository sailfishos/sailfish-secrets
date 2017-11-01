INCLUDEPATH += $$PWD
DEPENDPATH = $$INCLUDEPATH
PKGCONFIG += libcrypto

HEADERS += \
    $$PWD/secrets_p.h \
    $$PWD/secretsrequestprocessor_p.h \
    $$PWD/secretsdatabase_p.h \
    $$PWD/applicationpermissions_p.h

SOURCES += \
    $$PWD/secrets.cpp \
    $$PWD/secretsrequestprocessor.cpp \
    $$PWD/secretsdatabase.cpp \
    $$PWD/applicationpermissions.cpp

SOURCES += \
    $$PWD/secretscryptohelpers.cpp

