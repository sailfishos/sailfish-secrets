TEMPLATE = lib
TARGET = sailfishsecretsplugin
TARGET = $$qtLibraryTarget($$TARGET)
CONFIG += plugin hide_symbols
QT = qml quick gui core

include($$PWD/../../common.pri)
include($$PWD/../../lib/libsailfishsecrets.pri)

HEADERS += \
    $$PWD/plugintypes.h \
    $$PWD/applicationinteractionview.h \
    $$PWD/applicationinteractionview_p.h \
    $$PWD/findsecretsrequestwrapper.h

SOURCES += \
    $$PWD/main.cpp \
    $$PWD/applicationinteractionview.cpp \
    $$PWD/findsecretsrequestwrapper.cpp

OTHER_FILES += \
    $$PWD/defaultInteractionView.qml \
    $$PWD/InteractionView.qml \
    $$PWD/qmldir \
    $$PWD/plugins.qmltypes

RESOURCES += $$PWD/resources.qrc

target.path = $$[QT_INSTALL_LIBS]/qt5/qml/Sailfish/Secrets/
qmlfiles.path = $$[QT_INSTALL_LIBS]/qt5/qml/Sailfish/Secrets/
qmlfiles.files += InteractionView.qml qmldir plugins.qmltypes

INSTALLS += target qmlfiles

# Copy files to output directory so that the user can use the QML module from source tree,
# eg. in case the module is used on desktop
copydata.commands = $(COPY_DIR) $$PWD/qmldir $$PWD/plugins.qmltypes $$PWD/InteractionView.qml $$OUT_PWD || echo "copy not needed"
first.depends = $(first) copydata
export(first.depends)
export(copydata.commands)
QMAKE_EXTRA_TARGETS += first copydata

# Invoke directly to deal with circular dependency with silica submodules - keep
# just the Sailfish.Silica.private dependency to break the cycle.
qtPrepareTool(QMLIMPORTSCANNER, qmlimportscanner)
qmltypes.commands = \
    echo -e $$shell_quote('import Sailfish.Secrets 1.0\nQtObject{}\n') \
        |$$QMLIMPORTSCANNER -qmlFiles - -importPath $$[QT_INSTALL_QML] \
        |sed -e $$shell_quote('/"Sailfish.Silica"/,/{/d') \
        |sed -e $$shell_quote('/"Sailfish.Silica.Background"/,/{/d') > dependencies.json && \
    qmlplugindump -nonrelocatable -dependencies dependencies.json \
         Sailfish.Secrets 1.0 > $$PWD/plugins.qmltypes
QMAKE_EXTRA_TARGETS += qmltypes
