TEMPLATE = lib
TARGET = sailfishcryptoplugin
TARGET = $$qtLibraryTarget($$TARGET)
CONFIG += plugin hide_symbols
QT = qml core

include($$PWD/../../common.pri)
include($$PWD/../../lib/libsailfishcrypto.pri)

HEADERS += \
    $$PWD/plugintypes.h \
    $$PWD/storedkeyidentifiersrequestwrapper.h

SOURCES += \
    $$PWD/main.cpp \
    $$PWD/storedkeyidentifiersrequestwrapper.cpp

OTHER_FILES += $$PWD/qmldir $$PWD/plugins.qmltypes

target.path = $$[QT_INSTALL_LIBS]/qt5/qml/Sailfish/Crypto/
qmlfiles.path = $$[QT_INSTALL_LIBS]/qt5/qml/Sailfish/Crypto/
qmlfiles.files += qmldir plugins.qmltypes

INSTALLS += target qmlfiles

# Copy files to output directory so that the user can use the QML module from source tree,
# eg. in case the module is used on desktop
copydata.commands = $(COPY_DIR) $$PWD/qmldir $$PWD/plugins.qmltypes $$OUT_PWD || echo "copy not needed"
first.depends = $(first) copydata
export(first.depends)
export(copydata.commands)
QMAKE_EXTRA_TARGETS += first copydata

qmltypes.commands = qmlplugindump -nonrelocatable Sailfish.Crypto 1.0 > $$PWD/plugins.qmltypes
QMAKE_EXTRA_TARGETS += qmltypes
