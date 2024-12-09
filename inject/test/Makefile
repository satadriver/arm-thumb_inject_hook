SRCS = $(wildcard *.c *.s *.cpp)
OBJS = $(SRCS:.c = .o .cpp = .o .s = .o)
CC = arm-linux-gnueabihf-gcc
#INCLUDES = -I/×××
#LIBS = -L/×××
CCFLAGS = -g -Wall -O0 -static
test: $(OBJS)
	$(CC) $^ -o $@
%.o : %.c %.s %.cpp
	$(CC) -c $< $(CCFLAGS)
clean:
	rm *.o ./test
.PHONY:clean
