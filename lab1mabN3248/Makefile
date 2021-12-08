CFLAGS = -O2 -Wall -Wextra -Werror
TARGETS = lab1mabN3248 lib1mabN3248.so libavg.so

.PHONY: all clean

all: $(TARGETS)

clean:
	rm -rf *.o $(TARGETS)

lab1mabN3248: lab1mabN3248.c plugin_api.h
	gcc $(CFLAGS) -o lab1mabN3248 lab1mabN3248.c -ldl

lib1mabN3248.so: lib1mabN3248.c plugin_api.h
	gcc $(CFLAGS) -shared -fPIC -o lib1mabN3248.so lib1mabN3248.c -ldl

libavg.so: libavg.c plugin_api.h
	gcc $(CFLAGS) -shared -fPIC libavg.c -o libavg.so -ldl -lm