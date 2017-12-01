TEMPLATE = lib
CONFIG += plugin
TARGET = sailfishsecrets-testsqlite
TARGET = $$qtLibraryTarget($$TARGET)

include($$PWD/../../../common.pri)
include($$PWD/../../../api/libsailfishsecrets/libsailfishsecrets.pri)
include($$PWD/../../../database/database.pri)

DEFINES += SAILFISH_SECRETS_BUILD_TEST_PLUGIN
HEADERS += $$PWD/../../sqliteplugin/sqlitedatabase_p.h $$PWD/../../sqliteplugin/plugin.h
SOURCES += $$PWD/../../sqliteplugin/plugin.cpp

target.path=/usr/lib/sailfishsecrets/
INSTALLS += target
