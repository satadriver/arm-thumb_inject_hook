SRCS = $(wildcard *.c *.s *.cpp)
OBJS = $(SRCS:.c = .o .cpp = .o .s = .o)
CC = arm-linux-gnueabihf-gcc
#INCLUDES = -I/×××
#LIBS = -L/×××
CCFLAGS = -g -Wall -O0
inject : $(OBJS)
	$(CC) $^ -o $@
%.o : %.c %.s %.cpp
	$(CC) -c $< $(CCFLAGS)
clean:
	rm *.o ./inject
.PHONY:clean

#$@  obj
#$^  所有的依赖文件
#$<  第一个依赖文件
#$?  比目标还要新的依赖文件列表
