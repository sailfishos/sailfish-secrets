TEMPLATE = lib
CONFIG += plugin
TARGET = sailfishsecrets-testsqlite
TARGET = $$qtLibraryTarget($$TARGET)

include($$PWD/../../../common.pri)
include($$PWD/../../../lib/libsailfishsecrets.pri)
include($$PWD/../../../database/database.pri)

DEFINES += SAILFISHSECRETS_TESTPLUGIN

HEADERS += \
    $$PWD/../../../plugins/sqliteplugin/sqlitedatabase_p.h \
    $$PWD/../../../plugins/sqliteplugin/plugin.h

SOURCES += \
    $$PWD/../../../plugins/sqliteplugin/plugin.cpp

target.path=/usr/lib/Sailfish/Secrets/
INSTALLS += target
