.RECIPEPREFIX = >
CC      := gcc
CFLAGS  := -O2 -Wall -Wextra                                      
TARGETS := bistro-builder aegis-init libaegis_ratchet.so aegis-vpatch aegis-audit aegis-privsep libaegis_privsep.so

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

aegis-audit: aegis_audit.c
> $(CC) $(CFLAGS) $< -o $@

aegis-privsep: aegis_privsep.c
> $(CC) $(CFLAGS) $< -o $@
                                                                  libaegis_privsep.so: aegis_privsep.c
> $(CC) $(CFLAGS) -fPIC -shared -DAEGIS_PRIVSEP_SHIM $< -o $@ -ldl -lpthread

clean:
> rm -f $(TARGETS)
