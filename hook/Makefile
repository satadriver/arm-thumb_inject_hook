SRCS = $(wildcard *.c *.s *.cpp)
OBJS = $(SRCS:.c = .o .cpp = .o .s = .o)
CC = arm-linux-gnueabihf-g++
#INCLUDES = -I/×××
#LIBS = -L/×××
CCFLAGS = -g -Wall -O0 -lc -lstdc++
hook : $(OBJS)
	$(CC) $^ -o $@
%.o : %.c %.s %.cpp
	$(CC) -c $< $(CCFLAGS)
clean:
	rm *.o
.PHONY:clean
