TEMPLATE = lib
CONFIG += plugin hide_symbols link_pkgconfig
TARGET = sailfishsecrets-passwordagentauth
TARGET = $$qtLibraryTarget($$TARGET)
PKGCONFIG += nemodevicelock

include($$PWD/../../common.pri)
include($$PWD/../../lib/libsailfishsecretspluginapi.pri)

HEADERS += passwordagentplugin.h
SOURCES += passwordagentplugin.cpp
OTHER_FILES += org.sailfishos.secrets.policy

polkitactions.files = org.sailfishos.secrets.policy
polkitactions.path = /usr/share/polkit-1/actions

target.path=/usr/lib/Sailfish/Secrets/

INSTALLS += \
    polkitactions \
    target
