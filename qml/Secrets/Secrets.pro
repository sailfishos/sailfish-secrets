TEMPLATE = lib
TARGET = sailfishsecretsplugin
TARGET = $$qtLibraryTarget($$TARGET)
CONFIG += plugin hide_symbols

include($$PWD/../../common.pri)
include($$PWD/../../lib/libsailfishsecrets.pri)

QT += qml quick gui core

HEADERS += \
    $$PWD/plugintypes.h \
    $$PWD/applicationinteractionview.h \
    $$PWD/applicationinteractionview_p.h

SOURCES += \
    $$PWD/main.cpp \
    $$PWD/applicationinteractionview.cpp

OTHER_FILES += \
    $$PWD/defaultInteractionView.qml \
    $$PWD/InteractionView.qml \
    $$PWD/qmldir

RESOURCES += $$PWD/resources.qrc

target.path = /usr/lib/qt5/qml/Sailfish/Secrets/
qmlfiles.path = /usr/lib/qt5/qml/Sailfish/Secrets/
qmlfiles.files += InteractionView.qml qmldir

INSTALLS += target qmlfiles

# Copy files to output directory so that the user can use the QML module from source tree,
# eg. in case the module is used on desktop
copydata.commands = $(COPY_DIR) $$PWD/qmldir $$PWD/InteractionView.qml $$OUT_PWD || echo "copy not needed"
first.depends = $(first) copydata
export(first.depends)
export(copydata.commands)
QMAKE_EXTRA_TARGETS += first copydata
