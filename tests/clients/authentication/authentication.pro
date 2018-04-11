TEMPLATE = app
TARGET = authentication-client

include($$PWD/../../../lib/libsailfishsecrets.pri)

CONFIG += \
    link_pkgconfig

SOURCES += main.cpp

PKGCONFIG += \
    qt5-boostable

target.path = /opt/tests/Sailfish/Secrets/

INSTALLS += target
