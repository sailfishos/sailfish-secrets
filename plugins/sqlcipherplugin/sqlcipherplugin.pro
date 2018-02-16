TEMPLATE = lib
CONFIG += plugin
TARGET = sailfishsecrets-sqlcipher
TARGET = $$qtLibraryTarget($$TARGET)

include($$PWD/../../common.pri)
include($$PWD/../../lib/libsailfishsecrets.pri)
include($$PWD/../../lib/libsailfishcrypto.pri)
include($$PWD/../../database/database.pri)

HEADERS += \
    $$PWD/../opensslcryptoplugin/evp_p.h \
    $$PWD/sqlcipherplugin.h

SOURCES += \
    $$PWD/sqlcipherplugin.cpp \
    $$PWD/encryptedstorageplugin.cpp \
    $$PWD/cryptoplugin.cpp

OTHER_FILES += \
    $$PWD/../opensslcryptoplugin/cryptoplugin_common.cpp

target.path=/usr/lib/Sailfish/Secrets/
INSTALLS += target
