# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -Wextra -std=c11

# Source files
SRC = dhcomply.c dhcomplyFunctions.c dhcomplyStandardLibrary.c

# Object files (same names, .o extension)
OBJ = $(SRC:.c=.o)

# Output executable
OUT = dhcomply

# Default target
all: $(OUT)

# Link the object files to create executable
$(OUT): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(OUT)

# Compile .c to .o
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	rm -f $(OBJ) $(OUT)
