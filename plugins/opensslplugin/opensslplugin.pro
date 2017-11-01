TEMPLATE=lib
CONFIG+=plugin
TARGET=sailfishsecrets-openssl
TARGET = $$qtLibraryTarget($$TARGET)

include($$PWD/../../common.pri)
include($$PWD/../../api/libsailfishsecrets/libsailfishsecrets.pri)

HEADERS+=evp_p.h plugin.h
SOURCES+=plugin.cpp

target.path=/usr/lib/sailfishsecrets/
INSTALLS += target
