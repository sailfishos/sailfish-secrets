TEMPLATE = lib
TARGET = sailfishsecretsplugin
TARGET = $$qtLibraryTarget($$TARGET)
CONFIG += plugin

include($$PWD/../../common.pri)
include($$PWD/../../lib/secrets/libsailfishsecrets.pri)

QT += qml quick gui core

HEADERS += \
    $$PWD/inprocessuiview.h \
    $$PWD/inprocessuiview_p.h

SOURCES += \
    $$PWD/main.cpp \
    $$PWD/inprocessuiview.cpp

OTHER_FILES += \
    $$PWD/defaultUiView.qml \
    $$PWD/UiView.qml \
    $$PWD/qmldir

RESOURCES += $$PWD/resources.qrc

target.path = /usr/lib/qt5/qml/Sailfish/Secrets/
qmlfiles.path = /usr/lib/qt5/qml/Sailfish/Secrets/
qmlfiles.files += UiView.qml qmldir

INSTALLS += target qmlfiles
