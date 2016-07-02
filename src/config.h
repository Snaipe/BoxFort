/*
 * The MIT License (MIT)
 *
 * Copyright © 2016 Franklin "Snaipe" Mathieu <http://snai.pe/>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#ifndef CONFIG_H_IN_
# define CONFIG_H_IN_

#define BXF_ARCH "x86_64"
#define BXF_BITS 64
#define BXF_MANGLING none

/* #undef BXF_ARCH_x86 */
#define BXF_ARCH_x86_64 1
/* #undef BXF_ARCH_ARM */
/* #undef BXF_ARCH_ARM64 */

#define BXF_EXE_FMT_ELF 1
/* #undef BXF_EXE_FMT_PE */
/* #undef BXF_EXE_FMT_MACH_O */

#define HAVE__R_DEBUG 1
#define HAVE__DYNAMIC 1
#define HAVE_ELF_AUXV_T 1
/* #undef HAVE_ELF_AUXINFO */

#endif /* !CONFIG_H_IN_ */
