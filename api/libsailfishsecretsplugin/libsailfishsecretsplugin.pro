TEMPLATE=lib
TARGET=sailfishsecretsplugin
TARGET = $$qtLibraryTarget($$TARGET)

include($$PWD/../../common.pri)
include($$PWD/../libsailfishsecrets/libsailfishsecrets.pri)

QT += qml quick gui core
CONFIG += plugin

HEADERS += \
    inprocessuiview.h \
    inprocessuiview_p.h

SOURCES += \
    main.cpp \
    inprocessuiview.cpp

OTHER_FILES += \
    defaultUiView.qml \
    UiView.qml \
    qmldir

RESOURCES += resources.qrc

target.path = /usr/lib/qt5/qml/org/sailfishos/secrets/
qmlfiles.path = /usr/lib/qt5/qml/org/sailfishos/secrets/
qmlfiles.files += UiView.qml qmldir

INSTALLS += target qmlfiles
