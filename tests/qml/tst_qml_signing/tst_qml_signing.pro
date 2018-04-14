TEMPLATE = app
TARGET = tst_qml_signing
target.path = /opt/tests/Sailfish/Crypto/

QT += testlib quick
CONFIG += qmltestcase

SOURCES += \
    tst_qml_signing.cpp

OTHER_FILES += \
    tst_qml_signing.qml

qmlfile.path = /opt/tests/Sailfish/Crypto
qmlfile.files = tst_qml_signing.qml

INSTALLS += target qmlfile
