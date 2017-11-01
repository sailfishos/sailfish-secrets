unix|macx {
    QMAKE_CXXFLAGS += -Werror

    # enable full stack traces at the expense of optimisation
    QMAKE_CXXFLAGS += -pg -O0 -g
}
win32 {
    win32-g++ {
        QMAKE_CXXFLAGS += -Werror
    } else {
        QMAKE_CXXFLAGS += /WX
    }
}
