TEMPLATE = app
TARGET = tst_masterkey
target.path = /opt/tests/Sailfish/Secrets/
QT += sql testlib
CONFIG += link_pkgconfig
PKGCONFIG += libcrypto
INSTALLS += target

HEADERS += \
    $$PWD/../../../daemon/SecretsImpl/dataprotector_p.h \
    $$PWD/../../../daemon/SecretsImpl/masterkeymanager_p.h \
    $$PWD/../../../daemon/SecretsImpl/appsupportkeystore_p.h \
    $$PWD/../../../database/database_p.h

SOURCES += \
    $$PWD/../../../daemon/SecretsImpl/dataprotector.cpp \
    $$PWD/../../../daemon/SecretsImpl/masterkeymanager.cpp \
    $$PWD/../../../daemon/SecretsImpl/appsupportkeystore.cpp \
    $$PWD/../../../database/database.cpp \
    $$PWD/tst_masterkey.cpp

INCLUDEPATH += $$PWD/../../../database
