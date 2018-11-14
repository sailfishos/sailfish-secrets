TEMPLATE = app
TARGET = tst_gnupgplugin

SOURCES += tst_gnupgplugin.cpp

target.path = /opt/tests/Sailfish/Crypto/
include($$PWD/../../../lib/libsailfishcrypto.pri)
QT += testlib
INSTALLS += target
