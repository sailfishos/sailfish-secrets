TEMPLATE = app
TARGET = tst_crypto
target.path = /opt/tests/Sailfish/Crypto/
include($$PWD/../../lib/libsailfishcrypto.pri)
QT += testlib
SOURCES += tst_crypto.cpp
INSTALLS += target
