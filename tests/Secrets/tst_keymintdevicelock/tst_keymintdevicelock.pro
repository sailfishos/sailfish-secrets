TEMPLATE = app
TARGET = tst_keymintdevicelock
target.path = /opt/tests/Sailfish/Secrets/

QT += testlib

include($$PWD/../../../lib/libsailfishcryptopluginapi.pri)

HEADERS += \
    $$PWD/../../../daemon/SecretsImpl/keymintdevicelocknotifier_p.h

SOURCES += \
    $$PWD/../../../daemon/SecretsImpl/keymintdevicelocknotifier.cpp \
    tst_keymintdevicelock.cpp

INSTALLS += target
