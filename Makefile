CC = gcc
CFLAGS = -Wall -Wextra -std=gnu99 -g -Ilib
LDFLAGS = -lm
BINDIR = bin
TARGET = $(BINDIR)/dhcomply

# Source files
SRCS = src/dhcomplyMain.c \
       src/dhcomplyLifeCycle.c \
       src/dhcomplyMessageFunctions.c \
       src/dhcomplyDHCPv6Functions.c \
       src/dhcomplyStandardLibrary.c \
       lib/cJSON.c

# Object files
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
