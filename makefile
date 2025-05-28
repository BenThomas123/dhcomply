CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g

# Source files
SRCS = dhcomplyMain.c dhcomplyFunctions.c dhcomplyStandardLibrary.c

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
