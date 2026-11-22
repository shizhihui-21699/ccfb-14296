CC      = cc
CFLAGS  = -O2 -Wall -Wextra -std=c11
LDLIBS  = -lm
SRC     = src/dram.c src/alloc.c src/spage.c src/sim.c src/main.c

rhsim: $(SRC) src/rh.h
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDLIBS)

clean:
	rm -f rhsim results.csv

.PHONY: clean
