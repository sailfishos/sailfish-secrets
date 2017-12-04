TEMPLATE = lib
TARGET = sailfishsecretsplugin
TARGET = $$qtLibraryTarget($$TARGET)
CONFIG += plugin

include($$PWD/../../common.pri)
include($$PWD/../../lib/secrets/libsailfishsecrets.pri)

QT += qml quick gui core

HEADERS += \
    $$PWD/inprocessinteractionview.h \
    $$PWD/inprocessinteractionview_p.h

SOURCES += \
    $$PWD/main.cpp \
    $$PWD/inprocessinteractionview.cpp

OTHER_FILES += \
    $$PWD/defaultInteractionView.qml \
    $$PWD/InteractionView.qml \
    $$PWD/qmldir

RESOURCES += $$PWD/resources.qrc

target.path = /usr/lib/qt5/qml/Sailfish/Secrets/
qmlfiles.path = /usr/lib/qt5/qml/Sailfish/Secrets/
qmlfiles.files += InteractionView.qml qmldir

INSTALLS += target qmlfiles
