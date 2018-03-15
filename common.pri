unix|macx {
    QMAKE_CXXFLAGS += -Werror

    # This is to allow sailfish-secrets to build with OpenSSL 1.1.0
    QMAKE_CXXFLAGS += -Wno-error=deprecated-declarations -Wdeprecated-declarations
}
