.RECIPEPREFIX = >
CC      := gcc
CFLAGS  := -O2 -Wall -Wextra

TARGETS := bistro-builder aegis-init libaegis_ratchet.so aegis-vpatch

.PHONY: all clean

all: $(TARGETS)

bistro-builder: bistro_hardened_builder.c
> $(CC) $(CFLAGS) $< -o $@

aegis-init: aegis_init.c
> $(CC) $(CFLAGS) $< -o $@

libaegis_ratchet.so: aegis_ratchet.c
> $(CC) $(CFLAGS) -fPIC -shared $< -o $@ -ldl

aegis-vpatch: aegis_vpatch.c
> $(CC) $(CFLAGS) -pthread $< -o $@

clean:
> rm -f $(TARGETS)
