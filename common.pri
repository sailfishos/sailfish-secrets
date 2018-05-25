unix|macx {
    QMAKE_CXXFLAGS += -Werror
}

QT -= gui
CONFIG += rtti_off
CONFIG += c++11
