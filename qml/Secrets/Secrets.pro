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
