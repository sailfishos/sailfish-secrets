TEMPLATE = app
TARGET = tst_cryptosecrets
target.path = /opt/tests/Sailfish/Crypto/
include($$PWD/../../lib/crypto/libsailfishcrypto.pri)
include($$PWD/../../lib/secrets/libsailfishsecrets.pri)
QT += testlib
SOURCES += tst_cryptosecrets.cpp
INSTALLS += target
