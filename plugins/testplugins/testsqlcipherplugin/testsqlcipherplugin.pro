TEMPLATE=lib
CONFIG+=plugin
TARGET=sailfishsecrets-testsqlcipher
TARGET = $$qtLibraryTarget($$TARGET)

include($$PWD/../../../common.pri)
include($$PWD/../../../api/libsailfishsecrets/libsailfishsecrets.pri)
include($$PWD/../../../database/database.pri)

DEFINES+=SAILFISH_SECRETS_BUILD_TEST_PLUGIN
HEADERS+=$$PWD/../../sqlcipherplugin/plugin.h
SOURCES+=$$PWD/../../sqlcipherplugin/plugin.cpp

target.path=/usr/lib/sailfishsecrets/
INSTALLS += target
