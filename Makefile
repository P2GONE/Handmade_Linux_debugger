# Makefile

CC = gcc
CFLAGS = -Wall -g
LIBS = -lcapstone

# 소스 파일 목록
SRCS = main.c disass.c ptrace.c breakpoint.c
OBJS = $(SRCS:.c=.o)

# 실행 파일 이름
TARGET = my_debugger

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
