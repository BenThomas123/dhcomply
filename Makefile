CC = gcc
CFLAGS = -Wall -Wextra -std=gnu99 -g -Ilib
LDFLAGS = -lm
ifeq ($(WERROR),1)
CFLAGS += -Werror -Wa,--fatal-warnings
LDFLAGS += -Wl,--fatal-warnings
endif

BINDIR = bin
TARGET = $(BINDIR)/dhcomply
DAD_SCRIPT = $(BINDIR)/check_dad.sh
TEST_BUILD_DIR = build/unit-tests

# Source files
SRCS = src/dhcomplyMain.c \
       src/dhcomplyLifeCycle.c \
       src/dhcomplyBuildMessageFunctions.c \
       src/dhcomplyParseMessageFunctions.c \
       src/dhcomplySendMessageFunctions.c \
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
	$(CC) $(CFLAGS) -c -g $< -o $@

test:
	cmake -S . -B "$(TEST_BUILD_DIR)" -DBUILD_TESTING=ON
	cmake --build "$(TEST_BUILD_DIR)"
	ctest --test-dir "$(TEST_BUILD_DIR)" --output-on-failure --no-tests=error

clean:
	rm -f $(OBJS) $(TARGET) $(DAD_SCRIPT)

.PHONY: all clean test
