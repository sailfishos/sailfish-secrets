TEMPLATE = app
TARGET = tst_dataprotection
target.path = /opt/tests/Sailfish/Secrets/
QT += testlib gui qml quick
INSTALLS += target

HEADERS += \
    $$PWD/../../../daemon/SecretsImpl/dataprotector_p.h \
    $$PWD/tst_dataprotection.h

SOURCES += \
    $$PWD/../../../daemon/SecretsImpl/dataprotector.cpp \
    $$PWD/tst_dataprotection.cpp
