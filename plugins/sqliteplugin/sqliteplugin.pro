TEMPLATE=lib
CONFIG+=plugin
TARGET=sailfishsecrets-sqlite
TARGET = $$qtLibraryTarget($$TARGET)

include($$PWD/../../common.pri)
include($$PWD/../../api/libsailfishsecrets/libsailfishsecrets.pri)
include($$PWD/../../database/database.pri)

HEADERS+=sqlitedatabase_p.h plugin.h
SOURCES+=plugin.cpp

target.path=/usr/lib/sailfishsecrets/
INSTALLS += target
