TEMPLATE = app
TARGET = tst_crypto_capi
target.path = /opt/tests/Sailfish/Crypto/
include($$PWD/../../lib/libsailfishcrypto.pri)
CONFIG -= qt
SOURCES += tst_crypto_capi.c
INSTALLS += target
