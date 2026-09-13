TEMPLATE = app
TARGET = tst_freshauth
target.path = /opt/tests/Sailfish/Secrets/
include($$PWD/../../../lib/libsailfishsecrets.pri)
QT += testlib
SOURCES += tst_freshauth.cpp
INSTALLS += target
