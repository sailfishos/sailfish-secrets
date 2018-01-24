TEMPLATE = lib
CONFIG += plugin
TARGET = sailfishsecrets-sqlite
TARGET = $$qtLibraryTarget($$TARGET)

include($$PWD/../../common.pri)
include($$PWD/../../lib/libsailfishsecrets.pri)
include($$PWD/../../database/database.pri)

HEADERS += $$PWD/sqlitedatabase_p.h $$PWD/plugin.h
SOURCES += $$PWD/plugin.cpp

target.path=/usr/lib/Sailfish/Secrets/
INSTALLS += target
