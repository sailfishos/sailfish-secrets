TEMPLATE=lib
CONFIG+=plugin
TARGET=sailfishsecrets-testsqlite
TARGET = $$qtLibraryTarget($$TARGET)

include($$PWD/../../../common.pri)
include($$PWD/../../../api/libsailfishsecrets/libsailfishsecrets.pri)

DEFINES+=SAILFISH_SECRETS_BUILD_TEST_PLUGIN
HEADERS+=$$PWD/../../sqliteplugin/database_p.h $$PWD/../../sqliteplugin/plugin.h
SOURCES+=$$PWD/../../sqliteplugin/database.cpp $$PWD/../../sqliteplugin/plugin.cpp

target.path=/usr/lib/sailfishsecrets/
INSTALLS += target
