
TARGET=bogons
CXXFLAGS=-O2 -std=c++11


all: $(TARGET)

$(TARGET): main.o Bogons.o rwfile.o network.o
	g++ -o $@ $^
	strip $@

clean:
	-rm $(TARGET)
	-rm *.o


install: $(TARGET)
	install $(TARGET) /usr/local/bin
