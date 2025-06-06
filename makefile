CC = gcc
CFLAGS = -Wall -Wextra -std=gnu99 -g

# Source files
SRCS = src/dhcomplyMain.c src/dhcomplyFunctions.c src/dhcomplyStandardLibrary.c

# Object files
OBJS = $(SRCS:.c=.o)

# Output executable
TARGET = dhcomply

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
