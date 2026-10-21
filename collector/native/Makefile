CLANG ?= clang
CC ?= cc
BPFTOOL ?= $(shell command -v bpftool)
BUILD := build
CFLAGS := -O2 -g -Wall -Wextra -Werror
.PHONY: all clean
all: $(BUILD)/iotguard-sensor
$(BUILD):
	mkdir -p $@
$(BUILD)/vmlinux.h: | $(BUILD)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@.tmp
	mv $@.tmp $@
$(BUILD)/guard.bpf.o: guard.bpf.c event.h $(BUILD)/vmlinux.h
	$(CLANG) -g -O2 -target bpf -Wall -Werror -I$(BUILD) -c $< -o $@
$(BUILD)/guard.skel.h: $(BUILD)/guard.bpf.o
	$(BPFTOOL) gen skeleton $< > $@.tmp
	mv $@.tmp $@
$(BUILD)/iotguard-sensor: sensor.c event.h $(BUILD)/guard.skel.h
	$(CC) $(CFLAGS) -I$(BUILD) sensor.c -o $@ $$(pkg-config --cflags --libs libbpf) -lelf -lz
clean:
	rm -f $(BUILD)/iotguard-sensor $(BUILD)/guard.bpf.o $(BUILD)/guard.skel.h $(BUILD)/vmlinux.h
