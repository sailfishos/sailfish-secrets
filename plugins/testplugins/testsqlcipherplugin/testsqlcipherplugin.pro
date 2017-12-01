TEMPLATE = lib
CONFIG += plugin
TARGET = sailfishsecrets-testsqlcipher
TARGET = $$qtLibraryTarget($$TARGET)

include($$PWD/../../../common.pri)
include($$PWD/../../../api/libsailfishsecrets/libsailfishsecrets.pri)
include($$PWD/../../../api/libsailfishcrypto/libsailfishcrypto.pri)
include($$PWD/../../../database/database.pri)

DEFINES += SAILFISH_SECRETS_BUILD_TEST_PLUGIN

HEADERS += \
    $$PWD/../../opensslcryptoplugin/evp_p.h \
    $$PWD/../../sqlcipherplugin/sqlcipherplugin.h

SOURCES += \
    $$PWD/../../sqlcipherplugin/sqlcipherplugin.cpp \
    $$PWD/../../sqlcipherplugin/encryptedstorageplugin.cpp \
    $$PWD/../../sqlcipherplugin/cryptoplugin.cpp

OTHER_FILES += \
    $$PWD/../../opensslcryptoplugin/cryptoplugin_common.cpp

target.path=/usr/lib/sailfishsecrets/
INSTALLS += target
