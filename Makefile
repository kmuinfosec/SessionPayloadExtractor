CXX=g++
CFLAGS=-std=c++17
INC=-Isrc
LIBS=-lpcap
OBJS=main.o spe.o

all: main.o spe.o
	$(CXX) $(OBJS) -o SPE $(LIBS)
	rm -f $(OBJS)

main.o: src/common.h
	$(CXX) $(CFLAGS) $(INC) -c src/main.cpp

spe.o: src/spe.h src/common.h
	$(CXX) $(CFLAGS) $(INC) -c src/spe.cpp

.PHONY: clean
clean:
	rm -f $(OBJS) SPE