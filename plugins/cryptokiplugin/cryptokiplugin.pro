TEMPLATE=lib
CONFIG+=plugin
TARGET=cryptoki
TARGET = $$qtLibraryTarget($$TARGET)

include($$PWD/../../common.pri)
include($$PWD/../../api/libsailfishcrypto/libsailfishcrypto.pri)

HEADERS+=plugin.h
SOURCES+=plugin.cpp

target.path=/usr/lib/sailfishcrypto/
INSTALLS += target
