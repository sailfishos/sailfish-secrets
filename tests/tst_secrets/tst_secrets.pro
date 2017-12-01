TEMPLATE = app
TARGET = tst_secrets
target.path = /opt/tests/Sailfish/Secrets/
include($$PWD/../../lib/secrets/libsailfishsecrets.pri)
QT += testlib gui qml quick
SOURCES += tst_secrets.cpp
OTHER_FILES += tst_secrets.qml
testdata.files += tst_secrets.qml
testdata.path = /opt/tests/Sailfish/Secrets/
INSTALLS += target testdata
