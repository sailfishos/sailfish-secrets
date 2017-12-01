TEMPLATE = app
TARGET = tst_cryptosecrets
target.path = /opt/tests/Sailfish/Crypto/
include($$PWD/../../api/libsailfishcrypto/libsailfishcrypto.pri)
include($$PWD/../../api/libsailfishsecrets/libsailfishsecrets.pri)
QT += testlib
SOURCES += tst_cryptosecrets.cpp
INSTALLS += target
