TEMPLATE = app
TARGET = tst_cryptorequests
target.path = /opt/tests/Sailfish/Crypto/
include($$PWD/../../../lib/libsailfishcrypto.pri)
include($$PWD/../../../lib/libsailfishsecrets.pri)
QT += testlib
SOURCES += tst_cryptorequests.cpp
INSTALLS += target
