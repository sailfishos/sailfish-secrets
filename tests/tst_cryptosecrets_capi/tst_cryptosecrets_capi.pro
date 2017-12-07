TEMPLATE = app
TARGET = tst_cryptosecrets_capi
target.path = /opt/tests/Sailfish/Crypto/
include($$PWD/../../lib/libsailfishcrypto.pri)
include($$PWD/../../lib/libsailfishsecrets.pri)
CONFIG -= qt
SOURCES += tst_cryptosecrets_capi.c
INSTALLS += target
