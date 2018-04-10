TEMPLATE = lib
TARGET = sailfishcryptoplugin
TARGET = $$qtLibraryTarget($$TARGET)
CONFIG += plugin hide_symbols

include($$PWD/../../common.pri)
include($$PWD/../../lib/libsailfishcrypto.pri)

QT += qml core

HEADERS += \
    $$PWD/plugintypes.h \
    $$PWD/storedkeyidentifiersrequestwrapper.h

SOURCES += \
    $$PWD/main.cpp \
    $$PWD/storedkeyidentifiersrequestwrapper.cpp

OTHER_FILES += $$PWD/qmldir

target.path = /usr/lib/qt5/qml/Sailfish/Crypto/
qmlfiles.path = /usr/lib/qt5/qml/Sailfish/Crypto/
qmlfiles.files += qmldir

INSTALLS += target qmlfiles

# Copy files to output directory so that the user can use the QML module from source tree,
# eg. in case the module is used on desktop
copydata.commands = $(COPY_DIR) $$PWD/qmldir $$OUT_PWD || echo "copy not needed"
first.depends = $(first) copydata
export(first.depends)
export(copydata.commands)
QMAKE_EXTRA_TARGETS += first copydata
