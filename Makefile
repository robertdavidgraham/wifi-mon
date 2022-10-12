# This will point to the root of the project
LIBS = -ldl -lpcap -lpthread
INCLUDES = 

CC = gcc
CFLAGS = -g $(INCLUDES) -Wall -Wextra -Wpedantic -O3

.SUFFIXES: .c .cpp


tmp/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

SRC = $(sort $(wildcard src/*.c))
OBJ = $(addprefix tmp/, $(notdir $(addsuffix .o, $(basename $(SRC)))))

bin/wifi-mon: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) -lm $(LIBS) -lstdc++

depend:
	makedepend $(CFLAGS) -Y $(SRC)

clean:
	rm -f $(OBJ)

