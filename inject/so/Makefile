SRCS = $(wildcard *.c *.s *.cpp)
OBJS = $(SRCS:.c = .o .cpp = .o .s = .o)
CC = arm-linux-gnueabihf-gcc
#INCLUDES = -I/×××
#LIBS = -L/×××
CCFLAGS = -shared -g -Wall -O0
injected.so: $(OBJS)
	$(CC) -shared $^ -o $@
%.o : %.c %.s %.cpp
	$(CC) -c $< $(CCFLAGS)
clean:
	rm *.o ./injected.so
.PHONY:clean
