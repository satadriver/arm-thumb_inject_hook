SRCS = $(wildcard *.c *.s *.cpp)
OBJS = $(SRCS:.c = .o .cpp = .o .s = .o)
CC = arm-linux-gnueabihf-gcc
#INCLUDES = -I/×××
#LIBS = -L/×××
LDFLAGS = -shared -fPIC
CCFLAGS = -m64 -g -Wall -O0
hook64.so : $(OBJS)
	$(CC) $^ -o $@ $(LDFLAGS)
%.o : %.c %.s %.cpp
	$(CC) -c $< $(CCFLAGS)
clean:
	rm *.o hook64.so
.PHONY:clean
