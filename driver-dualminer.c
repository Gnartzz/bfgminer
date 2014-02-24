/*
 * Copyright 2013 Luke Dashjr
 * Copyright 2014 Nate Woolls
 * Copyright 2014 Dualminer Team
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "config.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "miner.h"
#include "icarus-common.h"
#include "lowlevel.h"
#include "lowl-vcom.h"
#include "deviceapi.h"
#include "logging.h"
#include "util.h"
#include "gc3355.h"

#ifndef WIN32
  #include <sys/ioctl.h>
#else
  #include <io.h>
#endif

#define DUALMINER_IO_SPEED 115200
#define DUALMINER_HASH_TIME 0.00001250

bool opt_dualminer_test = false;

#define RTS_LOW 0
#define RTS_HIGH 1
#define LTC_UNIT_CLOSE 1

BFG_REGISTER_DRIVER(dualminer_drv)

static
bool dualminer_detect_init(const char *devpath, int fd)
{
	char *dualnonce;
	unsigned char my_bin[52], scrypt_bin[160];
	int i = 2;    //0x000187a2 - 0x000187a0

	gc3355_dual_reset(fd);

	opt_ltconly ? gc3355_opt_ltc_only_init(fd) : gc3355_dualminer_init(fd);

	return true;
}

static
bool dualminer_job_start_init(const char *devpath, int fd)
{
	if (opt_scrypt)
		gc3355_opt_scrypt_init(fd);
	else
		gc3355_dualminer_init(fd);

	return true;
}

static
bool dualminer_detect_one(const char *devpath)
{
	struct device_drv *drv = &dualminer_drv;

	struct ICARUS_INFO *info = calloc(1, sizeof(struct ICARUS_INFO));
	if (unlikely(!info))
		quit(1, "Failed to malloc ICARUS_INFO");

	*info = (struct ICARUS_INFO){
		.baud = DUALMINER_IO_SPEED,
		.Hs = DUALMINER_HASH_TIME,
		.timing_mode = MODE_DEFAULT,
		.reopen_mode = IRM_NEVER,
		.do_icarus_timing = false,
		.reverse_nonce = true,
		.work_division = 2,
		.fpga_count = 2,
		.detect_init_func = dualminer_detect_init,
		.job_start_init_func = dualminer_job_start_init
	};


	if (opt_scrypt)
	{
		info->golden_ob = "55aa1f00000000000000000000000000000000000000000000000000aaaaaaaa711c0000603ebdb6e35b05223c54f8155ac33123006b4192e7aafafbeb9ef6544d2973d700000002069b9f9e3ce8a6778dea3d7a00926cd6eaa9585502c9b83a5601f198d7fbf09be9559d6335ebad363e4f147a8d9934006963030b4e54c408c837ebc2eeac129852a55fee1b1d88f6000c050000000600";
		info->golden_nonce = "00050cdd";
		info->work_size = 160;
	}
	else
	{
		info->golden_ob = "55aa0f00a08701004a548fe471fa3a9a1371144556c3f64d2500b4826008fe4bbf7698c94eba7946ce22a72f4f6726141a0b3287";
		info->golden_nonce = "000187a2";
		info->work_size = 52;
	}

	if (!icarus_detect_custom(devpath, drv, info))
	{
		free(info);
		return false;
	}

	if (opt_scrypt)
		info->read_count = 48;
	else
		info->read_count = 16;

	return true;
}

static
bool dualminer_lowl_probe(const struct lowlevel_device_info * const info)
{
	return vcom_lowl_probe_wrapper(info, dualminer_detect_one);
}

static
char *dualminer_set_device(struct cgpu_info *cgpu, char *option, char *setting, char *replybuf)
{
//	if (strcasecmp(option, "ltc_only") == 0)
//	{
//		return dualminer_ltc_only(cgpu, setting, replybuf);
//	}

	sprintf(replybuf, "Unknown option: %s", option);
	return replybuf;
}

static
bool dualminer_thread_init(struct thr_info *thr)
{
	struct cgpu_info *icarus = thr->cgpu;
	struct ICARUS_INFO *info = icarus->device_data;
	int fd = icarus->device_fd;

	if(opt_dualminer_test || opt_scrypt)
		set_serial_rts(fd, RTS_HIGH);

	if(!opt_dualminer_test)
		gc3355_init(fd, opt_dualminer_pll, opt_dualminer_btc_gating, opt_ltconly);

	if (opt_scrypt)
		icarus->min_nonce_diff = 1./0x10000;

	applog(LOG_DEBUG, "dualminer: Init: pll=%d, btcnum=%d", opt_pll_freq, opt_btc_number);

	return true;
}

static
void dualminer_thread_shutdown(struct thr_info *thr)
{
	if(!opt_dualminer_test)
	{
		if(opt_scrypt)
		{
			gc3355_open_ltc_unit(thr->cgpu->device_fd, LTC_UNIT_CLOSE);
		}
		else
		{
			gc3355_open_btc_unit(thr->cgpu->device_fd, "0");
		}
		set_serial_rts(thr->cgpu->device_fd, RTS_LOW);
		do_icarus_close(thr);
	}

	free(thr->cgpu_data);
}

static
bool dualminer_job_prepare(struct thr_info *thr, struct work *work, __maybe_unused uint64_t max_nonce)
{
	struct cgpu_info * const icarus = thr->cgpu;
	struct icarus_state * const state = thr->cgpu_data;
	struct ICARUS_INFO * const info = icarus->device_data;
	int fd = icarus->device_fd;

	memset(state->ob_bin, 0, info->work_size);

	if(opt_scrypt)
	{
		state->ob_bin[0] = 0x55;
		state->ob_bin[1] = 0xaa;
		state->ob_bin[2] = 0x1f;
		state->ob_bin[3] = 0x00;
		memcpy(state->ob_bin + 4, work->target, 32);
		memcpy(state->ob_bin + 36, work->midstate, 32);
		memcpy(state->ob_bin + 68, work->data, 80);
		state->ob_bin[148] = 0xff;
		state->ob_bin[149] = 0xff;
		state->ob_bin[150] = 0xff;
		state->ob_bin[151] = 0xff;
	}
	else
	{
		uint8_t temp_bin[64];
		memset(temp_bin, 0, 64);
		memcpy(temp_bin, work->midstate, 32);
		memcpy(temp_bin+52, work->data + 64, 12);
		state->ob_bin[0] = 0x55;
		state->ob_bin[1] = 0xaa;
		state->ob_bin[2] = 0x0f;
		state->ob_bin[3] = 0x00;
		memcpy(state->ob_bin + 8, temp_bin, 32);
		memcpy(state->ob_bin + 40, temp_bin + 52, 12);
	}

	return true;
}

static
void dualminer_drv_init()
{
	dualminer_drv = icarus_drv;
	dualminer_drv.dname = "dualminer";
	dualminer_drv.name = "DMR";
	dualminer_drv.lowl_probe = dualminer_lowl_probe;
	dualminer_drv.set_device = dualminer_set_device;
	dualminer_drv.thread_init = dualminer_thread_init;
	dualminer_drv.thread_shutdown = dualminer_thread_shutdown;
	dualminer_drv.job_prepare = dualminer_job_prepare;
	++dualminer_drv.probe_priority;
}

struct device_drv dualminer_drv =
{
	.drv_init = dualminer_drv_init,
};
