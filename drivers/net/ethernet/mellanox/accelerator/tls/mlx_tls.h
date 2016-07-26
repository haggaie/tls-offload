/*
 * Copyright (c) 2015-2016 Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#ifndef MLX_ACCEL_H
#define MLX_ACCEL_H

#include <linux/fs.h>

#define DEVICE_NAME "mlx_tls"
#define MLX_ACCEL_VERSION (1)
/* This is an experimental Ethertype field allocated for public use. */
#define MLX_ACCEL_ETHERTYPE  (0x88B5)
#define MLX_ACCEL_BULK_SKB_READ ((size_t)~0)
struct attach_ioctl {
	unsigned int version;
	int sockfd;
	unsigned int config_len;
};

struct attach_identity_ioctl {
	struct attach_ioctl attach;
	unsigned int config_id;
};

struct attach_xor_ioctl {
	struct attach_ioctl attach;
	unsigned int config_id;
	unsigned char start_byte;
};

/* [BP]: TODO - maybe choose a different magic('\xff') */
#define MLX_IOCTL_ACCEL_ATTACH_SOCKET_RX _IOW('\xff', 0, struct attach_ioctl)
#define MLX_IOCTL_ACCEL_ATTACH_SOCKET_TX _IOW('\xff', 1, struct attach_ioctl)

#define DIRECTION_RX (1)
#define DIRECTION_TX (2)
#define GET_DIRECTION(x) ((x == MLX_IOCTL_ACCEL_ATTACH_SOCKET_RX) ? \
						DIRECTION_RX : DIRECTION_TX)

#define MLX_ACCEL_VERSION (1)

#define CONFIG_ID_IDENTITY (1)
#define CONFIG_ID_XOR (2)
#define CONFIG_ID_TLS (3)

#endif
