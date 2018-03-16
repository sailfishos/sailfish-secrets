TEMPLATE = lib
CONFIG += plugin hide_symbols
TARGET = sailfishsecrets-sqlcipher
TARGET = $$qtLibraryTarget($$TARGET)

include($$PWD/../../common.pri)
include($$PWD/../../lib/libsailfishsecrets.pri)
include($$PWD/../../lib/libsailfishcrypto.pri)
include($$PWD/../../database/database.pri)

INCLUDEPATH += $$PWD/../opensslcryptoplugin/evp/
DEPENDPATH += $$PWD/../opensslcryptoplugin/evp/

HEADERS += \
    $$PWD/../opensslcryptoplugin/evp/evp_p.h \
    $$PWD/sqlcipherplugin.h

SOURCES += \
    $$PWD/../opensslcryptoplugin/evp/evp.c \
    $$PWD/sqlcipherplugin.cpp \
    $$PWD/encryptedstorageplugin.cpp \
    $$PWD/cryptoplugin.cpp

OTHER_FILES += \
    $$PWD/../opensslcryptoplugin/cryptoplugin_common.cpp

target.path=/usr/lib/Sailfish/Secrets/
INSTALLS += target
