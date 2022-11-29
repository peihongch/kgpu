/* This work is licensed under the terms of the GNU GPL, version 2.  See
 * the GPL-COPYING file in the top-level directory.
 *
 * Copyright (c) 2010-2011 University of Utah and the Flux Group.
 * All rights reserved.
 *
 * KGPU GAES header
 */

#ifndef __GAESK_H__
#define __GAESK_H__

#include "gaes_common.h"

#define GECB_SIZE_THRESHOLD (1 * PAGE_SIZE)
#define GCTR_SIZE_THRESHOLD (1 * PAGE_SIZE)
#define GXTS_SIZE_THRESHOLD (1 * PAGE_SIZE)

#define GAUTHENC_SIZE_THRESHOLD (512)

long test_gecb(size_t sz, int enc);
long test_gctr(size_t sz);
long test_glctr(size_t sz);

static void cvt_endian_u32(u32* buf, int n) {
    u8* b = (u8*)buf;
    int nb = n * 4;

    u8 t;
    int i;

    for (i = 0; i < nb; i += 4, b += 4) {
        t = b[0];
        b[0] = b[3];
        b[3] = t;

        t = b[1];
        b[1] = b[2];
        b[2] = t;
    }
}

#endif
