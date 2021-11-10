TEMPLATE = app
TARGET = tst_qml_rsaencryptdecrypt
target.path = /opt/tests/Sailfish/Crypto/

QT += testlib quick
CONFIG += qmltestcase

SOURCES += \
    tst_qml_rsaencryptdecrypt.cpp

OTHER_FILES += \
    tst_qml_rsaencryptdecrypt.qml

qmlfile.path = /opt/tests/Sailfish/Crypto
qmlfile.files = tst_qml_rsaencryptdecrypt.qml

INSTALLS += target qmlfile
