TEMPLATE = app
TARGET = tst_secrets_capi
target.path = /opt/tests/Sailfish/Secrets/
include($$PWD/../../lib/libsailfishsecrets.pri)
CONFIG -= qt
SOURCES += tst_secrets_capi.c
INSTALLS += target
