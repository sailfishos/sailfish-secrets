TEMPLATE = app
TARGET = sailfishsecretsd
QT = core sql dbus concurrent
CONFIG += link_pkgconfig hide_symbols
PKGCONFIG += dbus-1 Qt5Concurrent Qt5DBus Qt5Core Qt5Sql systemsettings

DEFINES += \
    PLUGIN_DIRECTORY_SECRETS=\"\\\"$$[QT_INSTALL_LIBS]/Sailfish/Secrets\\\"\" \
    PLUGIN_DIRECTORY_CRYPTO=\"\\\"$$[QT_INSTALL_LIBS]/Sailfish/Crypto\\\"\"

packagesExist(qt5-boostable) {
    DEFINES += HAS_BOOSTER
    PKGCONFIG += qt5-boostable
} else {
    warning("qt5-boostable not available; startup times will be slower")
}

packagesExist(nemonotifications-qt5) {
    PKGCONFIG += nemonotifications-qt5
    DEFINES += HAS_NEMO_NOTIFICATIONS
} else {
    warning("package nemonotifications-qt5 is not present, building without notification support")
}

include($$PWD/../common.pri)
include($$PWD/../lib/libsailfishsecrets.pri)
include($$PWD/../lib/libsailfishsecretspluginapi.pri)
include($$PWD/../lib/libsailfishcrypto.pri)
include($$PWD/../lib/libsailfishcryptopluginapi.pri)

HEADERS += \
    $$PWD/controller_p.h \
    $$PWD/discoveryobject_p.h \
    $$PWD/logging_p.h \
    $$PWD/plugin_p.h \
    $$PWD/requestqueue_p.h

SOURCES += \
    $$PWD/controller.cpp \
    $$PWD/plugin_p.cpp \
    $$PWD/requestqueue.cpp \
    $$PWD/main.cpp

include($$PWD/SecretsImpl/SecretsImpl.pri)
include($$PWD/CryptoImpl/CryptoImpl.pri)

# translations
TS_FILE = $$OUT_PWD/sailfish-secrets.ts
EE_QM = $$OUT_PWD/sailfish-secrets_eng_en.qm

ts.commands += lupdate $$PWD -ts $$TS_FILE
ts.CONFIG += no_check_exist
ts.output = $$TS_FILE
ts.input = $$PWD

ts_install.files = $$TS_FILE
ts_install.path = /usr/share/translations/source
ts_install.CONFIG += no_check_exist

engineering_english.commands += lrelease -idbased $$TS_FILE -qm $$EE_QM
engineering_english.CONFIG += no_check_exist
engineering_english.depends = ts
engineering_english.input = $$TS_FILE
engineering_english.output = $$EE_QM

engineering_english_install.path = /usr/share/translations
engineering_english_install.files = $$EE_QM
engineering_english_install.CONFIG += no_check_exist

QMAKE_EXTRA_TARGETS += ts engineering_english
PRE_TARGETDEPS += ts engineering_english

target.path = /usr/bin/
INSTALLS += target ts_install engineering_english_install
