TEMPLATE = app
TARGET = tst_cryptostorage
target.path = /opt/tests/Sailfish/Crypto/
include($$PWD/../../../lib/libsailfishcrypto.pri)
include($$PWD/../../../lib/libsailfishsecrets.pri)
QT += testlib
SOURCES += tst_cryptostorage.cpp
INSTALLS += target
