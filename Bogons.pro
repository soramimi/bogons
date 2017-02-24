TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

QMAKE_CXXFLAGS += -Wno-switch

SOURCES += \ 
    src/main.cpp \
    src/network.cpp \
    src/rwfile.cpp \
    src/Bogons.cpp

HEADERS += \
    src/network.h \
    src/rwfile.h \
    src/Bogons.h
