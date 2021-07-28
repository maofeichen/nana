DIR_SRC := ./src
DIR_OBJ := .
DIR_BIN := .

TARGETS := $(DIR_BIN)/nmon
SRC		 = $(wildcard $(DIR_SRC)/*.c)
OBJ		:= $(SRC:$(DIR_SRC)/%.c=$(DIR_OBJ)/%.o)

CC		= gcc
CCFLAG	= -g -Wall
CINC	= -lpcap

.PHONY: all clean
all: $(TARGETS) 

# Linking
$(TARGETS): $(OBJ) 
	$(CC) $(CINC) $^ -o $@

# For each source file, compile to its object file
$(OBJ): $(DIR_OBJ)/%.o: $(DIR_SRC)/%.c 
	$(CC) $(CFLAGS) -c $< -o $@

# For each source file, generate its dependencies
$(DIR_OBJ)/%.d: $(DIR_SRC)/%.c
	@set -e; rm -f $@; \
	$(CC) -MM $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

-include $(OBJ:.o=.d)

clean:
	# @echo $(OBJ)
	# @echo $(SRC)
	rm -f $(OBJ) $(TARGETS) $(OBJ:.o=.d)