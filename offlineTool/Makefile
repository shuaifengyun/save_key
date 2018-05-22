CC = gcc

OBJ_C = cryptoDebug.o\
		cryptoSha.o \
		cryptoAes.o \
		cryptoRsa.o \
		cryptoPbkdf.o \
		main.o

C_OBJDIR = obj

CFLAGS += -I ./include
#CFLAGS += -L /usr/lib/x86_64-linux-gnu/
CFLAGS += -lcrypto
#CFLAGS += -static
CFLAGS += -ldl
CFLAGS += -lm

TARGET = cryptoLinux

.PHONY: all setup clean


all: $(TARGET)

$(TARGET): $(OBJ_C)
	$(call test)
	@echo start to build binary
	$(CC) -o $(TARGET) $(C_OBJDIR)/* $(CFLAGS)

$(OBJ_C): %.o : %.c setup
	@echo  "=== Compiling  : $<"
	$(CC)  -o $@ -c $< $(CFLAGS)
	mv $@ $(C_OBJDIR)

setup:
	mkdir -p $(C_OBJDIR)

clean:
	rm -rf $(C_OBJDIR)
	rm -rf $(TARGET)


