CFLAGS = -O2 -Wall -Wextra -Werror
TARGETS = lab1mabN3248 lib1mabN3248.so lib1mabN3248.so.1.0.1 lib1mabN3248.so.1.0.2 libavg.so
CORRUPTED_TARGET = libcorrupted.so

.PHONY: all clean

all: $(TARGETS)

corrupted: $(CORRUPTED_TARGET)

clean:
	rm -rf *.o $(TARGETS) $(CORRUPTED_TARGET)

clean_corrupted:
	rm -rf $(CORRUPTED_TARGET)

lab1mabN3248: lab1mabN3248.c plugin_api.h
	gcc $(CFLAGS) -o lab1mabN3248 lab1mabN3248.c -ldl

lib1mabN3248.so: lib1mabN3248.c plugin_api.h
	gcc $(CFLAGS) -shared -fPIC -o lib1mabN3248.so lib1mabN3248.c -ldl

lib1mabN3248.so.1.0.1: lib1mabN3248.1.c plugin_api.h
	gcc $(CFLAGS) -shared -fPIC -o lib1mabN3248.so.1.0.1 lib1mabN3248.1.c -ldl

lib1mabN3248.so.1.0.2: lib1mabN3248.2.c plugin_api.h
	gcc $(CFLAGS) -shared -fPIC -o lib1mabN3248.so.1.0.2 lib1mabN3248.2.c -ldl

libavg.so: libavg.c plugin_api.h
	gcc $(CFLAGS) -shared -fPIC libavg.c -o libavg.so -ldl -lm

libcorrupted.so: libcorrupted.c 
	gcc $(CFLAGS) -shared -fPIC libcorrupted.c -o libcorrupted.so -ldl 