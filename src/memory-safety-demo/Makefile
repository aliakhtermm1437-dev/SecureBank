# SecureBank memory-safety demo — build matrix
#
# `make vuln`     – unsafe binary, no hardening
# `make hardened` – RELRO + NX + PIE + stack-canary + FORTIFY + format-security

CC ?= gcc

# Intentionally minimal flags — DO NOT enable hardening here.
VULN_CFLAGS  = -O0 -g -Wno-format-security -fno-stack-protector -no-pie -z execstack -Wno-deprecated-declarations

# Full hardening per ASVS V14, OWASP Secure Coding, BSI TR-03127
HARD_CFLAGS  = -O2 -g \
               -fPIE -pie \
               -fstack-protector-strong \
               -fstack-clash-protection \
               -D_FORTIFY_SOURCE=3 \
               -Wformat -Wformat-security -Werror=format-security \
               -Wall -Wextra -Wno-unused-parameter \
               -fcf-protection=full
HARD_LDFLAGS = -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack

all: vuln hardened

vuln: vuln.c
	$(CC) $(VULN_CFLAGS) -o $@ $<

hardened: hardened.c
	$(CC) $(HARD_CFLAGS) $(HARD_LDFLAGS) -o $@ $<

clean:
	rm -f vuln hardened core.* *.o

.PHONY: all clean
