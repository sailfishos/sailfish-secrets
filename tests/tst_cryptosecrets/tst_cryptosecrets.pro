TEMPLATE = app
TARGET = tst_cryptosecrets
target.path = /opt/tests/Sailfish/Crypto/
include($$PWD/../../lib/libsailfishcrypto.pri)
include($$PWD/../../lib/libsailfishsecrets.pri)
QT += testlib
SOURCES += tst_cryptosecrets.cpp
INSTALLS += target
