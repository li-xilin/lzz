CC = gcc
TARGET = lzz
OBJS = lzz.o main.o lznt1.o
CFLAGS += -g -O0
all: $(TARGET)
$(TARGET): $(OBJS)
	$(CC) -o $@ $^ -lm -laxkit -laxcore -lpthread

clean:
	$(RM) $(OBJS) $(TARGET)
