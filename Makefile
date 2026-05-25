CC = gcc
CFLAGS = -Wall -Wextra -std=gnu99 -g -Ilib
LDFLAGS = -lm
BINDIR = bin
TARGET = $(BINDIR)/dhcomply
DAD_SCRIPT = $(BINDIR)/check_dad.sh

# Source files
SRCS = src/dhcomplyMain.c \
       src/dhcomplyLifeCycle.c \
       src/dhcomplyMessageFunctions.c \
       src/dhcomplyDHCPv6Functions.c \
       src/dhcomplyStandardLibrary.c \
       lib/cJSON.c

# Object files
OBJS = $(SRCS:.c=.o)

all: $(TARGET) $(DAD_SCRIPT)

$(TARGET): $(OBJS) | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(DAD_SCRIPT): src/check_dad.sh | $(BINDIR)
	@cp $< $@
	@chmod +x $@

$(BINDIR):
	@mkdir -p $(BINDIR)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET) $(DAD_SCRIPT)

.PHONY: all clean
