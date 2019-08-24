TARGET = bogons
TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
DESTDIR = $$PWD/_bin

unix:QMAKE_CXXFLAGS += -Wno-switch

SOURCES += \ 
    src/main.cpp \
    src/network.cpp \
    src/rwfile.cpp \
    src/bogons.cpp

HEADERS += \
    src/network.h \
    src/rwfile.h \
    src/bogons.h
