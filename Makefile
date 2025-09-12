TARGET = nxpwifiutl
SRCS = nxpwifiutl.c
CFLAGS += $(shell pkg-config --cflags libnl-3.0 libnl-genl-3.0)
LDFLAGS += $(shell pkg-config --libs libnl-3.0 libnl-genl-3.0)

CC ?= aarch64-poky-linux-gcc

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)
