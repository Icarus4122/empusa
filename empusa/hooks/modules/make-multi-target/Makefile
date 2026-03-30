# make-multi-target - Cross-Platform Build
#
# Builds both Linux and Windows binaries from payload.c
#
# Usage:
#   make all         # Build both targets
#   make linux       # Linux only
#   make windows     # Windows only (needs mingw-w64)
#   make clean       # Remove build artifacts

CC_LINUX   = gcc
CC_WINDOWS = x86_64-w64-mingw32-gcc
SRC        = payload.c
BUILD      = build
OUT_LINUX  = $(BUILD)/payload
OUT_WIN    = $(BUILD)/payload.exe

.PHONY: all linux windows clean

all: linux windows

linux: $(BUILD)
	$(CC_LINUX) $(SRC) -o $(OUT_LINUX)
	@echo "[+] Built: $(OUT_LINUX)"

windows: $(BUILD)
	$(CC_WINDOWS) $(SRC) -o $(OUT_WIN)
	@echo "[+] Built: $(OUT_WIN)"

$(BUILD):
	mkdir -p $(BUILD)

clean:
	rm -rf $(BUILD)
	@echo "[*] Clean."
