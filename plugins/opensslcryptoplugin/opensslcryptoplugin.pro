TEMPLATE=lib
CONFIG+=plugin
TARGET=sailfishcrypto-openssl
TARGET = $$qtLibraryTarget($$TARGET)

include($$PWD/../../common.pri)
include($$PWD/../../api/libsailfishcrypto/libsailfishcrypto.pri)

HEADERS+=evp_p.h plugin.h
SOURCES+=plugin.cpp

target.path=/usr/lib/sailfishcrypto/
INSTALLS += target
