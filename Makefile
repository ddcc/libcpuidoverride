CFLAGS  += -g -O2 -fPIC -pie -Wall -fno-stack-protector -fvisibility=hidden
LDFLAGS += -fPIC -pie -static -nostdlib -Wl,-z,relro -Wl,-z,initfirst -Wl,-e_start

DEPS    = $(wildcard src/*.h)
SOURCES = $(wildcard src/*.c)
OBJECTS = $(SOURCES:.c=.o)
TARGET  = libcpuidoverride.so

$(TARGET): $(OBJECTS) $(DEPS)
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@

%.o: %.c $(DEPS)
	$(CC) -c $(CFLAGS) $< -o $@

%.o: %.c $(DEPS)
	$(CC) -c $(CFLAGS) $< -o $@

all: $(SOURCES) $(TARGET)

.PHONY: clean

clean:
	rm -f $(OBJECTS) $(TARGET)
