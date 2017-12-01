TEMPLATE = lib
TARGET = sailfishsecretsplugin
TARGET = $$qtLibraryTarget($$TARGET)
CONFIG += plugin

include($$PWD/../../common.pri)
include($$PWD/../libsailfishsecrets/libsailfishsecrets.pri)

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

target.path = /usr/lib/qt5/qml/org/sailfishos/secrets/
qmlfiles.path = /usr/lib/qt5/qml/org/sailfishos/secrets/
qmlfiles.files += UiView.qml qmldir

INSTALLS += target qmlfiles
