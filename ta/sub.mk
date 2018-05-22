global-incdirs-y += include
#global-incdirs-y += ../host/include
srcs-y += SaveKeyTaAes.c
srcs-y += SaveKeyTaEntry.c
srcs-y += SaveKeyTaHash.c
srcs-y += SaveKeyTaRsa.c
srcs-y += SaveKeyTaDebug.c
srcs-y += SaveKeyTaHandle.c
srcs-y += SaveKeyTaPbkdf2.c
srcs-y += SaveKeyTaBase64.c
srcs-y += SaveKeyTaSecStor.c

# To remove a certain compiler flag, add a line like this
#cflags-template_ta.c-y += -Wno-strict-prototypes
