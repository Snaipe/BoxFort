/*
 * Dear user,
 *
 * this file has been released under the Romantic WTF public license.
 * I hereby grant you an irrevocable license to do
 * WHAT THE GENTLE CARESS YOU WANT TO
 * with this lovely code.
 *
 * -- Alexey Sheplyakov <asheplyakov@altlinux.org>
 *
 * P.S.: Even though I poured my heart into this work I cannot provide any
 *       warranty regarding its fitness for any purpose. You acknowledge
 *       that I will not be held liable for any damage its use could incur.
 */

#include "config.h"
#include "mangling.h"

#ifdef ASSEMBLER_SUPPORTS_HIDDEN
.hidden MANGLE(bxfi_trampoline)
#endif
.globl MANGLE(bxfi_trampoline)
MANGLE(bxfi_trampoline):
/* All LoongArch instructions are 4 bytes long.
 * The destination address is next to the trampoline code.
 * Thus the destination address is at current PC + 12 bytes
 * for the trampoline code is the following 3 instructions:
 */
    pcaddu12i	$t0, 0
    ld.d	$t0, $t0, 0xc
    jirl	$ra, $t0, 0

.align 1

#ifdef ASSEMBLER_SUPPORTS_HIDDEN
.hidden MANGLE(bxfi_trampoline_addr)
#endif
.globl MANGLE(bxfi_trampoline_addr)
MANGLE(bxfi_trampoline_addr):
addr_data:
.fill 8, 1, 0

#ifdef ASSEMBLER_SUPPORTS_HIDDEN
.hidden MANGLE(bxfi_trampoline_end)
#endif
.globl MANGLE(bxfi_trampoline_end)
MANGLE(bxfi_trampoline_end):

#include "stackfix.h"
