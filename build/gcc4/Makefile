# This will point to the root of the project
SRCDIR = ../../src
DSTDIR = ../../bin
TMPDIR = ../../tmp

LIBS = -ldl -lpcap -lpthread
INCLUDES = -I. -I$(SRCDIR) -I$(SRCDIR)/module -DSTATICPCAP

CC = gcc
CFLAGS = -g $(INCLUDES) -Wall -O3

.SUFFIXES: .c .cpp


$(TMPDIR)/%.o: $(SRCDIR)/display/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TMPDIR)/%.o: $(SRCDIR)/module/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TMPDIR)/%.o: $(SRCDIR)/netstack/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TMPDIR)/%.o: $(SRCDIR)/sqdb/%.c
	$(CC) $(CFLAGS) -c $< -o $@


display_sources := $(wildcard $(SRCDIR)/display/*.c)
module_sources := $(wildcard $(SRCDIR)/module/*.c)
netstack_sources := $(wildcard $(SRCDIR)/netstack/*.c)
sqdb_sources := $(wildcard $(SRCDIR)/sqdb/*.c)

SRC = $(display_sources) $(module_sources) $(netstack_sources) $(sqdb_sources)

OBJ = $(addprefix $(TMPDIR)/, $(notdir $(addsuffix .o, $(basename $(SRC))))) $(TMPDIR)/squirrel.o

$(DSTDIR)/squirrel: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) -lm $(LIBS) -lstdc++

depend:
	makedepend $(CFLAGS) -Y $(SRC)

clean:
	rm -f $(OBJ)

$(TMPDIR)/squirrel.o: $(SRCDIR)/squirrel.c
	$(CC) $(CFLAGS) -c $< -o $@

