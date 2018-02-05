TEMPLATE = app
TARGET = tst_secretsrequests
target.path = /opt/tests/Sailfish/Secrets/
include($$PWD/../../../lib/libsailfishsecrets.pri)
QT += testlib gui qml quick
SOURCES += tst_secretsrequests.cpp
OTHER_FILES += tst_secretsrequests.qml
testdata.files += tst_secretsrequests.qml
testdata.path = /opt/tests/Sailfish/Secrets/
INSTALLS += target testdata
