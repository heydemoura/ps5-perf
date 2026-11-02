include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
burner.elf: main.c
	$(CC) -O1 -g -fno-omit-frame-pointer -fno-optimize-sibling-calls -o $@ $< -lpthread
