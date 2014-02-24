/*
 * Copyright 2012-2013 Luke Dashjr
 * Copyright 2012 Xiangfu
 * Copyright 2012 Andrew Smith
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

/*
 * Those code should be works fine with V2 and V3 bitstream of Icarus.
 * Operation:
 *   No detection implement.
 *   Input: 64B = 32B midstate + 20B fill bytes + last 12 bytes of block head.
 *   Return: send back 32bits immediately when Icarus found a valid nonce.
 *           no query protocol implemented here, if no data send back in ~11.3
 *           seconds (full cover time on 32bit nonce range by 380MH/s speed)
 *           just send another work.
 * Notice:
 *   1. Icarus will start calculate when you push a work to them, even they
 *      are busy.
 *   2. The 2 FPGAs on Icarus will distribute the job, one will calculate the
 *      0 ~ 7FFFFFFF, another one will cover the 80000000 ~ FFFFFFFF.
 *   3. It's possible for 2 FPGAs both find valid nonce in the meantime, the 2
 *      valid nonce will all be send back.
 *   4. Icarus will stop work when: a valid nonce has been found or 32 bits
 *      nonce range is completely calculated.
 */

#include "config.h"
#include "miner.h"

#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#ifndef WIN32
  #include <termios.h>
  #include <sys/stat.h>
  #include <sys/ioctl.h>
  #include <fcntl.h>
  #ifndef O_CLOEXEC
    #define O_CLOEXEC 0
  #endif
#else
  #include <windows.h>
  #include <io.h>
#endif
#ifdef HAVE_SYS_EPOLL_H
  #include <sys/epoll.h>
  #define HAVE_EPOLL
#endif

#include "compat.h"
#include "dynclock.h"
#include "icarus-common.h"
#include "lowl-vcom.h"
#include <ctype.h>

// The serial I/O speed - Linux uses a define 'B115200' in bits/termios.h
#define ICARUS_IO_SPEED 115200

// The number of bytes in a nonce (always 4)
// This is NOT the read-size for the Icarus driver
// That is defined in ICARUS_INFO->read_size
#define ICARUS_NONCE_SIZE 4

#define ASSERT1(condition) __maybe_unused static char sizeof_uint32_t_must_be_4[(condition)?1:-1]
ASSERT1(sizeof(uint32_t) == 4);

#define ICARUS_READ_TIME(baud, read_size) ((double)read_size * (double)8.0 / (double)(baud))

// Defined in deciseconds
// There's no need to have this bigger, since the overhead/latency of extra work
// is pretty small once you get beyond a 10s nonce range time and 10s also
// means that nothing slower than 429MH/s can go idle so most icarus devices
// will always mine without idling
#define ICARUS_READ_COUNT_LIMIT_MAX 100

// In timing mode: Default starting value until an estimate can be obtained
// 5 seconds allows for up to a ~840MH/s device
#define ICARUS_READ_COUNT_TIMING	(5 * TIME_FACTOR)

// For a standard Icarus REV3
#define ICARUS_REV3_HASH_TIME 0.00000000264083

// Icarus Rev3 doesn't send a completion message when it finishes
// the full nonce range, so to avoid being idle we must abort the
// work (by starting a new work) shortly before it finishes
//
// Thus we need to estimate 2 things:
//	1) How many hashes were done if the work was aborted
//	2) How high can the timeout be before the Icarus is idle,
//		to minimise the number of work started
//	We set 2) to 'the calculated estimate' - 1
//	to ensure the estimate ends before idle
//
// The simple calculation used is:
//	Tn = Total time in seconds to calculate n hashes
//	Hs = seconds per hash
//	Xn = number of hashes
//	W  = code overhead per work
//
// Rough but reasonable estimate:
//	Tn = Hs * Xn + W	(of the form y = mx + b)
//
// Thus:
//	Line of best fit (using least squares)
//
//	Hs = (n*Sum(XiTi)-Sum(Xi)*Sum(Ti))/(n*Sum(Xi^2)-Sum(Xi)^2)
//	W = Sum(Ti)/n - (Hs*Sum(Xi))/n
//
// N.B. W is less when aborting work since we aren't waiting for the reply
//	to be transferred back (ICARUS_READ_TIME)
//	Calculating the hashes aborted at n seconds is thus just n/Hs
//	(though this is still a slight overestimate due to code delays)
//

// Both below must be exceeded to complete a set of data
// Minimum how long after the first, the last data point must be
#define HISTORY_SEC 60
// Minimum how many points a single ICARUS_HISTORY should have
#define MIN_DATA_COUNT 5
// The value above used is doubled each history until it exceeds:
#define MAX_MIN_DATA_COUNT 100

#if (TIME_FACTOR != 10)
#error TIME_FACTOR must be 10
#endif

static struct timeval history_sec = { HISTORY_SEC, 0 };

static const char *MODE_DEFAULT_STR = "default";
static const char *MODE_SHORT_STR = "short";
static const char *MODE_SHORT_STREQ = "short=";
static const char *MODE_LONG_STR = "long";
static const char *MODE_LONG_STREQ = "long=";
static const char *MODE_VALUE_STR = "value";
static const char *MODE_UNKNOWN_STR = "unknown";

#define END_CONDITION 0x0000ffff
#define DEFAULT_DETECT_THRESHOLD 1





/* 
 ** BEGIN DUALMINER HACKING **
 ** BEGIN DUALMINER HACKING **
 ** BEGIN DUALMINER HACKING **
 ** BEGIN DUALMINER HACKING **
 ** BEGIN DUALMINER HACKING **
 ** BEGIN DUALMINER HACKING **
 ** BEGIN DUALMINER HACKING **
 */



#define DEFAULT_DELAY_TIME 2000

#define HUBFANS_0_9V_BTC "60"
#define HUBFANS_1_2V_BTC "0"
#define DEFAULT_0_9V_BTC "60"
#define DEFAULT_1_2V_BTC "0"

#define LTC_UNIT_OPEN  0
#define LTC_UNIT_CLOSE 1

#define RTS_LOW 0
#define RTS_HIGH 1

const char *pll_freq_1200M_cmd[] =
{
	"55AAEF000500E085",
	"55AA0FFFB02800C0",
	"",
};

const char *pll_freq_1100M_cmd[] =
{
	"55AAEF0005006085",
	"55AA0FFF4C2500C0",
	"",
};

const char *pll_freq_1000M_cmd[] =
{
	"55AAEF000500E084",
	"55AA0FFFE82100C0",
	"",
};

const char *pll_freq_950M_cmd[] =
{
	"55AAEF000500A084",
	"55AA0FFF362000C0",
	"",
};

const char *pll_freq_900M_cmd[] =
{
	"55AAEF0005006084",
	"55AA0FFF841E00C0",
	"",
};

const char *pll_freq_850M_cmd[] =
{
	"55AAEF0005002084",
	"55AA0FFFD21C00C0",
	"",
};

const char *pll_freq_800M_cmd[] =
{
	"55AAEF000500E083",
	"55AA0FFF201B00C0",
	"",
};

const char *pll_freq_750M_cmd[] =
{
	"55AAEF000500A083",
	"55AA0FFF6E1900C0",
	"",
};

const char *pll_freq_700M_cmd[] =
{
	"55AAEF0005006083",
	"55AA0FFFBC1700C0",
	"",
};

const char *pll_freq_650M_cmd[] =
{
	"55AAEF0005002083",
	"55AA0FFF0A1600C0",
	"",
};

const char *pll_freq_600M_cmd[] =
{
	"55AAEF000500E082",
	"55AA0FFF581400C0",
	"",
};

const char *pll_freq_550M_cmd[] =
{
	"55AAEF000500A082",
	"55AA0FFFA61200C0",
	"",
};

const char *pll_freq_500M_cmd[] =
{
	"55AAEF0005006082",
	"55AA0FFFF41000C0",
	"",
};

const char *pll_freq_400M_cmd[] =
{
	"55AAEF000500E081",
	"55AA0FFF900D00C0",
	"",
};

const char *btc_gating[] =
{
	"55AAEF0200000000",
	"55AAEF0300000000",
	"55AAEF0400000000",
	"55AAEF0500000000",
	"55AAEF0600000000",
	"",
};

const char *btc_single_open[] =
{
	"55AAEF0200000001",
	"55AAEF0200000003",
	"55AAEF0200000007",
	"55AAEF020000000F",
	"55AAEF020000001F",
	"55AAEF020000003F",
	"55AAEF020000007F",
	"55AAEF02000000FF",
	"55AAEF02000001FF",
	"55AAEF02000003FF",
	"55AAEF02000007FF",
	"55AAEF0200000FFF",
	"55AAEF0200001FFF",
	"55AAEF0200003FFF",
	"55AAEF0200007FFF",
	"55AAEF020000FFFF",
	"55AAEF020001FFFF",
	"55AAEF020003FFFF",
	"55AAEF020007FFFF",
	"55AAEF02000FFFFF",
	"55AAEF02001FFFFF",
	"55AAEF02003FFFFF",
	"55AAEF02007FFFFF",
	"55AAEF0200FFFFFF",
	"55AAEF0201FFFFFF",
	"55AAEF0203FFFFFF",
	"55AAEF0207FFFFFF",
	"55AAEF020FFFFFFF",
	"55AAEF021FFFFFFF",
	"55AAEF023FFFFFFF",
	"55AAEF027FFFFFFF",
	"55AAEF02FFFFFFFF",
	"55AAEF0300000001",
	"55AAEF0300000003",
	"55AAEF0300000007",
	"55AAEF030000000F",
	"55AAEF030000001F",
	"55AAEF030000003F",
	"55AAEF030000007F",
	"55AAEF03000000FF",
	"55AAEF03000001FF",
	"55AAEF03000003FF",
	"55AAEF03000007FF",
	"55AAEF0300000FFF",
	"55AAEF0300001FFF",
	"55AAEF0300003FFF",
	"55AAEF0300007FFF",
	"55AAEF030000FFFF",
	"55AAEF030001FFFF",
	"55AAEF030003FFFF",
	"55AAEF030007FFFF",
	"55AAEF03000FFFFF",
	"55AAEF03001FFFFF",
	"55AAEF03003FFFFF",
	"55AAEF03007FFFFF",
	"55AAEF0300FFFFFF",
	"55AAEF0301FFFFFF",
	"55AAEF0303FFFFFF",
	"55AAEF0307FFFFFF",
	"55AAEF030FFFFFFF",
	"55AAEF031FFFFFFF",
	"55AAEF033FFFFFFF",
	"55AAEF037FFFFFFF",
	"55AAEF03FFFFFFFF",
	"55AAEF0400000001",
	"55AAEF0400000003",
	"55AAEF0400000007",
	"55AAEF040000000F",
	"55AAEF040000001F",
	"55AAEF040000003F",
	"55AAEF040000007F",
	"55AAEF04000000FF",
	"55AAEF04000001FF",
	"55AAEF04000003FF",
	"55AAEF04000007FF",
	"55AAEF0400000FFF",
	"55AAEF0400001FFF",
	"55AAEF0400003FFF",
	"55AAEF0400007FFF",
	"55AAEF040000FFFF",
	"55AAEF040001FFFF",
	"55AAEF040003FFFF",
	"55AAEF040007FFFF",
	"55AAEF04000FFFFF",
	"55AAEF04001FFFFF",
	"55AAEF04003FFFFF",
	"55AAEF04007FFFFF",
	"55AAEF0400FFFFFF",
	"55AAEF0401FFFFFF",
	"55AAEF0403FFFFFF",
	"55AAEF0407FFFFFF",
	"55AAEF040FFFFFFF",
	"55AAEF041FFFFFFF",
	"55AAEF043FFFFFFF",
	"55AAEF047FFFFFFF",
	"55AAEF04FFFFFFFF",
	"55AAEF0500000001",
	"55AAEF0500000003",
	"55AAEF0500000007",
	"55AAEF050000000F",
	"55AAEF050000001F",
	"55AAEF050000003F",
	"55AAEF050000007F",
	"55AAEF05000000FF",
	"55AAEF05000001FF",
	"55AAEF05000003FF",
	"55AAEF05000007FF",
	"55AAEF0500000FFF",
	"55AAEF0500001FFF",
	"55AAEF0500003FFF",
	"55AAEF0500007FFF",
	"55AAEF050000FFFF",
	"55AAEF050001FFFF",
	"55AAEF050003FFFF",
	"55AAEF050007FFFF",
	"55AAEF05000FFFFF",
	"55AAEF05001FFFFF",
	"55AAEF05003FFFFF",
	"55AAEF05007FFFFF",
	"55AAEF0500FFFFFF",
	"55AAEF0501FFFFFF",
	"55AAEF0503FFFFFF",
	"55AAEF0507FFFFFF",
	"55AAEF050FFFFFFF",
	"55AAEF051FFFFFFF",
	"55AAEF053FFFFFFF",
	"55AAEF057FFFFFFF",
	"55AAEF05FFFFFFFF",
	"55AAEF0600000001",
	"55AAEF0600000003",
	"55AAEF0600000007",
	"55AAEF060000000F",
	"55AAEF060000001F",
	"55AAEF060000003F",
	"55AAEF060000007F",
	"55AAEF06000000FF",
	"55AAEF06000001FF",
	"55AAEF06000003FF",
	"55AAEF06000007FF",
	"55AAEF0600000FFF",
	"55AAEF0600001FFF",
	"55AAEF0600003FFF",
	"55AAEF0600007FFF",
	"55AAEF060000FFFF",
	"55AAEF060001FFFF",
	"55AAEF060003FFFF",
	"55AAEF060007FFFF",
	"55AAEF06000FFFFF",
	"55AAEF06001FFFFF",
	"55AAEF06003FFFFF",
	"55AAEF06007FFFFF",
	"55AAEF0600FFFFFF",
	"55AAEF0601FFFFFF",
	"55AAEF0603FFFFFF",
	"55AAEF0607FFFFFF",
	"55AAEF060FFFFFFF",
	"55AAEF061FFFFFFF",
	"55AAEF063FFFFFFF",
	"55AAEF067FFFFFFF",
	"55AAEF06FFFFFFFF",
	"",
};

const char *ltc_only_init[] =
{
	"55AAEF0200000000",
	"55AAEF0300000000",
	"55AAEF0400000000",
	"55AAEF0500000000",
	"55AAEF0600000000",
	"55AAEF3040000000",
	"55AA1F2810000000",
	"55AA1F2813000000",
	"",
};


char *opt_dualminer_pll = NULL;
bool opt_ltconly = true;
bool opt_hubfans;
bool opt_dualminer_test = false;
char *opt_dualminer_btc_gating = NULL;


static int opt_pll_freq=400;
static int opt_btc_number=160;


static unsigned char hex_str[2048];

static void print_hex(unsigned char *data, int len, const unsigned char * prefix)
{
    int             i, j, s, blank;
    unsigned char   *p=data;
    unsigned char *ptr=hex_str;

    memset(hex_str,0,sizeof(hex_str));
    if(prefix==NULL)
	{
        sprintf(ptr,"\n",prefix);
        ptr+=1;
    }
	else
	{
        sprintf(ptr,"%s",prefix);
        ptr+=strlen(prefix);
    }

    for(i=s=0; i<len; i++,p++)
	{
        if ((i%16)==0)
		{
            s = i;
            sprintf(ptr,"%04x :", i);
            ptr+=6;
        }
        sprintf(ptr," %02x", *p);
        ptr+=3;
        if (((i%16)==7) && (i!=(len-1)))
		{
            sprintf(ptr," -");
            ptr+=2;
        }
        else if ((i%16)==15)
		{
            sprintf(ptr,"    ");
            ptr+=4;
            for(j=s; j<=i; j++)
			{
                if (isprint(data[j]))
				{
                    sprintf(ptr,"%c", data[j]);
                    ptr+=1;
                }
                else
				{
                    sprintf(ptr,".");
                    ptr+=1;
                }
            }
            sprintf(ptr,"\n");
            ptr+=1;
        }
    }
    if ((i%16)!=0)
	{
        blank = ((16-i%16)*3+4) + (((i%16)<=8) ? 2 : 0);
        for(j=0; j<blank; j++)
		{
            sprintf(ptr," ");
            ptr+=1;
        }
        for(j=s; j<i; j++)
		{
            if (isprint(data[j]))
			{
                sprintf(ptr,"%c", data[j]);
                ptr+=1;
            }
            else
			{
                sprintf(ptr,".");
                ptr+=1;
            }
        }
        sprintf(ptr,"\n");
        ptr+=1;
    }

    applog(LOG_DEBUG, "%s", hex_str);
}

static int get_cts_status(int fd)
{
	int ret;
	int status = 0;
#ifdef WIN32
	GetCommModemStatus(_get_osfhandle(fd), &status);
	applog(LOG_DEBUG, "Get CTS Status is : %d [Windows: 0 is 1.2; 16 is 0.9]\n", status);
	ret = (status == 0) ? 1 : 0;
	return ret;
#else
	ioctl(fd, TIOCMGET, &status);
	ret = (status & 0x20) ? 0 : 1;
	applog(LOG_DEBUG, "Get CTS Status is : %d [Linux: 1 is 1.2; 0 is 0.9]\n", ret);
	return ret;

#endif
}

static void set_rts_status(int fd, unsigned int value)
{
#ifdef WIN32
	DCB dcb;
	memset(&dcb, 0, sizeof(DCB));
	GetCommState(_get_osfhandle(fd), &dcb);
	if(value != 0)
	{
		dcb.fRtsControl = RTS_CONTROL_ENABLE;
	}
	else
	{
		dcb.fRtsControl = RTS_CONTROL_DISABLE;
	}
	SetCommState(_get_osfhandle(fd), &dcb);
#else
	int rts_flag = 0;
	ioctl(fd, TIOCMGET, &rts_flag);
	if(value != 0)
	{
		rts_flag |= TIOCM_RTS; //√
	}
	else
	{
		rts_flag &= ~TIOCM_RTS;   //¡¡
	}
	ioctl(fd, TIOCMSET, &rts_flag);
#endif
}

static void dual_reset(int fd)
{
	static int i=0;
	applog(LOG_DEBUG,"--->>>%s():%d\n",__FUNCTION__,i++);

#ifdef WIN32
	DCB dcb;

	memset(&dcb, 0, sizeof(DCB));
	GetCommState(_get_osfhandle(fd), &dcb);
	dcb.fDtrControl = DTR_CONTROL_ENABLE;
	SetCommState(_get_osfhandle(fd), &dcb);
	Sleep(1);
	GetCommState(_get_osfhandle(fd), &dcb);
	dcb.fDtrControl = DTR_CONTROL_DISABLE;
	SetCommState(_get_osfhandle(fd), &dcb);

#else

	int dtr_flag = 0;
	ioctl(fd, TIOCMGET, &dtr_flag);
	dtr_flag |= TIOCM_DTR;
	ioctl(fd, TIOCMSET, &dtr_flag);
	usleep(1000);
	ioctl(fd, TIOCMGET, &dtr_flag);
	dtr_flag &= ~TIOCM_DTR;
	ioctl(fd, TIOCMSET, &dtr_flag);

#endif

}

static void gc3355_send_cmds(int fd, const char *cmds[])
{
	int i = 0;
	unsigned char ob_bin[32];
	for(i = 0 ;; i++)
	{
		memset(ob_bin, 0, sizeof(ob_bin));
		if (cmds[i][0] == 0)
		{
			break;
		}
		hex2bin(ob_bin, cmds[i], sizeof(ob_bin));
		icarus_write(fd, ob_bin, 8);
		usleep(DEFAULT_DELAY_TIME);
	}
}

static void opt_scrypt_init(int fd)
{
	const char initscrypt_ob[16][64] =
	{
		"55AA1F2810000000",
		"55AA1F2813000000",
		""
	};
	unsigned char ob_bin[32];
	int i;

	for(i = 0; i < 16; i++)
	{
		memset(ob_bin, 0, sizeof(ob_bin));
		if (initscrypt_ob[i][0] == '\0')
		{
			break;
		}
		else
		{
			hex2bin(ob_bin, initscrypt_ob[i], sizeof(ob_bin));
		}
		icarus_write(fd, ob_bin, 8);
		usleep(DEFAULT_DELAY_TIME);
	}
}

static void pll_freq_init(int fd, char *pll_freq)
{
	const char pll_freq_cmd[48][20] =
	{
		"400",
		"55AAEF000500E081",
		"55AA0FFF900D00C0",
		"1200",
		"55AAEF000500E085",
		"55AA0FFFB02800C0",
		"1100",
		"55AAEF0005006085",
		"55AA0FFF4C2500C0",
		"1000",
		"55AAEF000500E084",
		"55AA0FFFE82100C0",
		"950",
		"55AAEF000500A084",
		"55AA0FFF362000C0",
		"900",
		"55AAEF0005006084",
		"55AA0FFF841E00C0",
		"850",
		"55AAEF0005002084",
		"55AA0FFFD21C00C0",
		"800",
		"55AAEF000500E083",
		"55AA0FFF201B00C0",
		"750",
		"55AAEF000500A083",
		"55AA0FFF6E1900C0",
		"700",
		"55AAEF0005006083",
		"55AA0FFFBC1700C0",
		"650",
		"55AAEF0005002083",
		"55AA0FFF0A1600C0",
		"600",
		"55AAEF000500E082",
		"55AA0FFF581400C0",
		"550",
		"55AAEF000500A082",
		"55AA0FFFA61200C0",
		"500",
		"55AAEF0005006082",
		"55AA0FFFF41000C0",
	};
	unsigned char pllob_bin[10];
	int i;
	int found_pll = -1;

	if (pll_freq == NULL)
	{
		found_pll = 0;
	}
	else
	{
		for(i = 0; i < 48; i++)
		{

			if (pll_freq_cmd[i][0] == '\0')
			{
				break;
			}
			applog(LOG_DEBUG, "GC3355: pll_freq_cmd[i] is %s, freq %s \n",pll_freq_cmd[i],pll_freq);
			if (!strcmp(pll_freq, pll_freq_cmd[i]))
			{
				found_pll = i;
				opt_pll_freq=atoi(pll_freq);
			}
		}

		if(found_pll == -1)
		{
			found_pll = 0;
		}
	}

	if(found_pll != -1)
	{
		applog(LOG_DEBUG, "GC3355: found freq %s in the support list\n", pll_freq);
		memset(pllob_bin, 0, sizeof(pllob_bin));
		applog(LOG_DEBUG, "GC3355: set freq %s, reg1=%s in the support list\n", pll_freq, pll_freq_cmd[found_pll + 1]);
		hex2bin(pllob_bin, pll_freq_cmd[found_pll + 1], sizeof(pllob_bin));
		icarus_write(fd, pllob_bin, 8);
		usleep(1000);
		memset(pllob_bin, 0, sizeof(pllob_bin));
		applog(LOG_DEBUG, "GC3355: set freq %s, reg2=%s in the support list\n", pll_freq, pll_freq_cmd[found_pll + 2]);
		hex2bin(pllob_bin, pll_freq_cmd[found_pll + 2], sizeof(pllob_bin));
		icarus_write(fd, pllob_bin, 8);
		usleep(1000);
	}
	else
	{
		applog(LOG_ERR, "GC3355: freq %s is not supported\n", pll_freq);
	}
}

static void pll_freq_init2(int fd, char *pll_freq)
{
	int freq;
	if(pll_freq != NULL)
	{
		freq = atoi(pll_freq);
	}
	else
	{
		freq = 0;
	}

	opt_pll_freq = freq;
	switch(freq)
	{
		case 400:
		{
			gc3355_send_cmds(fd, pll_freq_400M_cmd);
			break;
		}
		case 500:
		{
			gc3355_send_cmds(fd, pll_freq_500M_cmd);
			break;
		}
		case 550:
		{
			gc3355_send_cmds(fd, pll_freq_550M_cmd);
			break;
		}
		case 600:
		{
			gc3355_send_cmds(fd, pll_freq_600M_cmd);
			break;
		}
		case 650:
		{
			gc3355_send_cmds(fd, pll_freq_650M_cmd);
			break;
		}
		case 700:
		{
			gc3355_send_cmds(fd, pll_freq_700M_cmd);
			break;
		}
		case 750:
		{
			gc3355_send_cmds(fd, pll_freq_750M_cmd);
			break;
		}
		case 800:
		{
			gc3355_send_cmds(fd, pll_freq_800M_cmd);
			break;
		}
		case 850:
		{
			gc3355_send_cmds(fd, pll_freq_850M_cmd);
			break;
		}
		case 900:
		{
			gc3355_send_cmds(fd, pll_freq_900M_cmd);
			break;
		}
		case 950:
		{
			gc3355_send_cmds(fd, pll_freq_950M_cmd);
			break;
		}
		case 1000:
		{
			gc3355_send_cmds(fd, pll_freq_1000M_cmd);
			break;
		}
		case 1100:
		{
			gc3355_send_cmds(fd, pll_freq_1100M_cmd);
			break;
		}
		case 1200:
		{
			gc3355_send_cmds(fd, pll_freq_1200M_cmd);
			break;
		}
		default: (get_cts_status(fd) == 1) ? gc3355_send_cmds(fd, pll_freq_850M_cmd) : gc3355_send_cmds(fd, pll_freq_550M_cmd);
	}
}


static void open_btc_unit(int fd, char *opt_btc_gating)
{
	unsigned char ob_bin[32];
	int i;
	//---btc unit---
	char btc_gating[5][17] =
	{
		"55AAEF0200000000",
		"55AAEF0300000000",
		"55AAEF0400000000",
		"55AAEF0500000000",
		"55AAEF0600000000",
	};
	union
	{
	    unsigned int i32[5];
	    unsigned char c8[20] ;
	}btc_group;

	int btc_number=0;
	if (opt_btc_gating== NULL)
	{
	    applog(LOG_DEBUG,"%s(): no --btc, use default 70 BTC Unit\n",__FUNCTION__);
	    btc_number = 70;
	}
	else
	{
	    applog(LOG_DEBUG,"%s(): %s:%d\n",__FUNCTION__, opt_btc_gating, atoi(opt_btc_gating));
	    if(atoi(opt_btc_gating)<=160 && atoi(opt_btc_gating)>=0)
		{
			btc_number = atoi(opt_btc_gating);
	    }
		else
		{
			applog(LOG_DEBUG,"%s():invalid btc number:%s:%d, use default 70 BTC Unit\n",__FUNCTION__,opt_btc_gating,atoi(opt_btc_gating));
			btc_number = 70;
	    }
	}

	for(i = 0; i < 5; i++)
	{
		btc_group.i32[i]=0;
		//printf("%s():0x%08x,\n",__FUNCTION__,btc_group.i32[i]);
	}

	for(i = 0; i < btc_number; i++)
	{
		btc_group.i32[i / 32] += 1 << ( i % 32);
		//printf("%d-%d: 0x%08x\n",i,i/32,btc_group.i32[i/32]);
	}
	for(i = 0; i < 5; i++)
	{
		//printf("%s():0x%08x,\n",__FUNCTION__,btc_group.i32[i]);
	}
	for(i = 0; i < 20; i++)
	{
		//printf("%s():0x%02x,\n",__FUNCTION__,btc_group.c8[i]);
	}
	for(i = 0; i < 20; i++)
	{
		sprintf(&btc_gating[i / 4][8 + (i % 4) * 2], "%02x", btc_group.c8[i]);
		//printf("%s():%s\n",__FUNCTION__,btc_gating[i/4]);
	}
	//---btc unit end---


	for(i = 0; i < 5; i++)
	{
		memset(ob_bin, 0, sizeof(ob_bin));

		if (btc_gating[i][0] == '\0')	break;
		hex2bin(ob_bin, btc_gating[i], sizeof(ob_bin));

		icarus_write(fd, ob_bin, 8);
		usleep(DEFAULT_DELAY_TIME);
	}
	opt_btc_number=btc_number;
}

static void open_btc_unit_single(int fd, unsigned int index)
{
	unsigned char ob_bin[32];
	int i;
	//---btc unit---
	char btc_gating[5][17] =
	{
		"55AAEF0200000000",
		"55AAEF0300000000",
		"55AAEF0400000000",
		"55AAEF0500000000",
		"55AAEF0600000000",
	};
	union
	{
	    unsigned int i32[5];
	    unsigned char c8[20] ;
	}btc_group;


	for(i=0;i<5;i++)
	{
		btc_group.i32[i]=0;
		//printf("%s():0x%08x,\n",__FUNCTION__,btc_group.i32[i]);
	}

    index = index%160;

	//for(i=0;i<btc_number;i++)
	{
		btc_group.i32[index/32] += 1<<( index%32);
		//printf("%d-%d: 0x%08x\n",i,i/32,btc_group.i32[i/32]);
	}
	for(i=0;i<5;i++)
	{
		//printf("%s():0x%08x,\n",__FUNCTION__,btc_group.i32[i]);
	}
	for(i=0;i<20;i++)
	{
		//printf("%s():0x%02x,\n",__FUNCTION__,btc_group.c8[i]);
	}
	for(i=0;i<20;i++)
	{
		sprintf(&btc_gating[i/4][8+(i%4)*2],"%02x",btc_group.c8[i]);
		//printf("%s():%s\n",__FUNCTION__,btc_gating[i/4]);
	}
	//---btc unit end---


	for(i=0; i<5; i++)
	{
		memset(ob_bin, 0, sizeof(ob_bin));

		if (btc_gating[i][0] == '\0')
		{
			break;
		}
		hex2bin(ob_bin, btc_gating[i], sizeof(ob_bin));

		icarus_write(fd, ob_bin, 8);
		usleep(DEFAULT_DELAY_TIME);
	}
}

static void open_btc_unit_one_by_one(int fd, char *opt_btc_gating)
{
	int unit_count = 0;
	unsigned char ob_bin[32];
	int i;
	unit_count = atoi(opt_btc_gating);
	if(unit_count < 0)
	{
		unit_count = 0;
	}
	if(unit_count > 160)
	{
		unit_count = 160;
	}
	if(unit_count > 0 && unit_count <= 160)
	{
		for(i = 0; i <= unit_count; i++)
		{
			memset(ob_bin, 0, sizeof(ob_bin));
			hex2bin(ob_bin, btc_single_open[i], sizeof(ob_bin));
			icarus_write(fd, ob_bin, 8);
			usleep(DEFAULT_DELAY_TIME * 2);
		}
		opt_btc_number=unit_count;
	}
	else if(unit_count == 0)
	{
		gc3355_send_cmds(fd, btc_gating);
	}
}

static void opt_ltc_only_init(int fd)
{
	const char init_ltc_only_ob[16][64] =
	{
		"55AAEF0200000000",
		"55AAEF0300000000",
		"55AAEF0400000000",
		"55AAEF0500000000",
		"55AAEF0600000000",
		"55AAEF3040000000",
		"55AA1F2810000000",
		"55AA1F2813000000",
		""
	};
	unsigned char ob_bin[32];
	int i;

	for(i = 0; i < 16; i++)
	{
		memset(ob_bin, 0, sizeof(ob_bin));

		if (init_ltc_only_ob[i][0] == '\0')
		{
			break;
		}
		hex2bin(ob_bin, init_ltc_only_ob[i], sizeof(ob_bin));

		icarus_write(fd, ob_bin, 8);
		usleep(DEFAULT_DELAY_TIME);
	}
	pll_freq_init2(fd, opt_dualminer_pll);
}


static void open_ltc_unit(int fd, int status)
{
	const char ltc_only_ob[16][64] =
	{
		"55AA1F2810000000",
		"",
	};

	const char ltc_ob[16][64] =
	{
		"55AA1F2814000000",
		"",
	};

	unsigned char ob_bin[32];
	int i = 0;
	if(status == LTC_UNIT_OPEN)
	{
		if(opt_ltconly)
		{
			opt_ltc_only_init(fd);
		}
		else
		{
			opt_scrypt_init(fd);
		}
	}
	else
	{
		for(i = 0; i < 16; i++)
		{
			memset(ob_bin, 0, sizeof(ob_bin));
			if(opt_ltconly)
			{
				if (ltc_only_ob[i][0] == '\0')
				{
					break;
				}
				else
				{
					hex2bin(ob_bin, ltc_only_ob[i], sizeof(ob_bin));
				}
			}
			else
			{
				if (ltc_ob[i][0] == '\0')
				{
					break;
				}
				else
				{
					hex2bin(ob_bin, ltc_ob[i], sizeof(ob_bin));
				}
			}
			icarus_write(fd, ob_bin, 8);
			usleep(DEFAULT_DELAY_TIME);
		}
	}
}

static void dualminer_init(int fd)
{

	const char init_ob[16][64] =
	{
#if 1
		"55AAEF0200000000",
		"55AAEF0300000000",
		"55AAEF0400000000",
		"55AAEF0500000000",
		"55AAEF0600000000",
#endif
		"55AAEF3020000000",
		"55AA1F2817000000",
		""
	};
	const char initscrypt_ob[16][64] =
	{
		"55AA1F2814000000",
		"55AA1F2817000000",
		""
	};

	unsigned char ob_bin[32];
	int i;

	for(i = 0; i < 16; i++)
	{
		memset(ob_bin, 0, sizeof(ob_bin));
		if (opt_scrypt)
		{
			if (initscrypt_ob[i][0] == '\0')	break;
			hex2bin(ob_bin, initscrypt_ob[i], sizeof(ob_bin));
		}
		else
		{
			if (init_ob[i][0] == '\0')	break;
			hex2bin(ob_bin, init_ob[i], sizeof(ob_bin));
		}

		icarus_write(fd, ob_bin, 8);
		usleep(DEFAULT_DELAY_TIME);
	}

	if (!opt_scrypt)
	{
		pll_freq_init2(fd, opt_dualminer_pll);
		//open_btc_unit(fd);
	}

	return;
}

static void gc3355_init(int fd, char *pll_freq, char *btc_unit, bool is_ltc_only)
{
	char *unit, *freq;
	if(get_cts_status(fd) == 1)    // 1.2v
	{
		if(opt_scrypt)
		{
			if(is_ltc_only)
			{
				gc3355_send_cmds(fd, ltc_only_init);
				//				opt_ltc_only_init(fd);
				//				(pll_freq == NULL) ? pll_freq_init2(fd, DEFAULT_1_2V_PLL) : 0;
				applog(LOG_DEBUG,"%s(): scrypt: %d, ltc only: %d; have fan: %d\n", __FUNCTION__, opt_scrypt, is_ltc_only, opt_hubfans);
			}
			else
			{
				//				dualminer_init(fd);
				applog(LOG_DEBUG,"%s(): scrypt: %d, ltc only: %d; have fan: %d\n", __FUNCTION__, opt_scrypt, is_ltc_only, opt_hubfans);
			}
		}
		else
		{
			//			(pll_freq == NULL) ? pll_freq_init2(fd, DEFAULT_1_2V_PLL) : 0;
			if(opt_hubfans)
			{
				//				((btc_unit == NULL) ? open_btc_unit(fd, HUBFANS_1_2V_BTC) : open_btc_unit(fd, btc_unit));
				((btc_unit == NULL) ? open_btc_unit_one_by_one(fd, HUBFANS_1_2V_BTC) : open_btc_unit_one_by_one(fd, btc_unit));
				applog(LOG_DEBUG,"%s(): scrypt: %d, ltc only: %d; have fan: %d\n", __FUNCTION__, opt_scrypt, is_ltc_only, opt_hubfans);
			}
			else
			{
				//				((btc_unit == NULL) ? open_btc_unit(fd, DEFAULT_1_2V_BTC) : open_btc_unit(fd, btc_unit));
				((btc_unit == NULL) ? open_btc_unit_one_by_one(fd, DEFAULT_1_2V_BTC) : open_btc_unit_one_by_one(fd, btc_unit));
				applog(LOG_DEBUG,"%s(): scrypt: %d, ltc only: %d; have fan: %d\n", __FUNCTION__, opt_scrypt, is_ltc_only, opt_hubfans);
			}
		}
	}
	else       //0.9v
	{
		if(opt_scrypt)
		{
			if(is_ltc_only)
			{
				//				opt_ltc_only_init(fd);
				gc3355_send_cmds(fd, ltc_only_init);
				//				(pll_freq == NULL) ? pll_freq_init2(fd, DEFAULT_0_9V_PLL) : 0;
				applog(LOG_DEBUG,"%s(): scrypt: %d, ltc only: %d; have fan: %d\n", __FUNCTION__, opt_scrypt, is_ltc_only, opt_hubfans);
			}
			else
			{
				//				dualminer_init(fd);
				applog(LOG_DEBUG,"%s(): scrypt: %d, ltc only: %d; have fan: %d\n", __FUNCTION__, opt_scrypt, is_ltc_only, opt_hubfans);
			}
		}
		else
		{
			//			(pll_freq == NULL) ? pll_freq_init2(fd, DEFAULT_0_9V_PLL) : 0;
			if(opt_hubfans)
			{
				((btc_unit == NULL) ? open_btc_unit_one_by_one(fd, HUBFANS_0_9V_BTC) : open_btc_unit_one_by_one(fd, btc_unit));
				//				((btc_unit == NULL) ? open_btc_unit(fd, HUBFANS_0_9V_BTC) : open_btc_unit(fd, btc_unit));
				applog(LOG_DEBUG,"%s(): scrypt: %d, ltc only: %d; have fan: %d\n", __FUNCTION__, opt_scrypt, is_ltc_only, opt_hubfans);
			}
			else
			{
				((btc_unit == NULL) ? open_btc_unit_one_by_one(fd, DEFAULT_0_9V_BTC) : open_btc_unit_one_by_one(fd, btc_unit));
				//				((btc_unit == NULL) ? open_btc_unit(fd, DEFAULT_0_9V_BTC) : open_btc_unit(fd, btc_unit));
				applog(LOG_DEBUG,"%s(): scrypt: %d, ltc only: %d; have fan: %d\n", __FUNCTION__, opt_scrypt, is_ltc_only, opt_hubfans);
			}
		}
	}
}



/*
 ** END DUALMINER HACKING **
 ** END DUALMINER HACKING **
 ** END DUALMINER HACKING **
 ** END DUALMINER HACKING **
 ** END DUALMINER HACKING **
 ** END DUALMINER HACKING **
 ** END DUALMINER HACKING **
 */





BFG_REGISTER_DRIVER(icarus_drv)
extern const struct bfg_set_device_definition icarus_set_device_funcs[];

extern void convert_icarus_to_cairnsmore(struct cgpu_info *);

static void rev(unsigned char *s, size_t l)
{
	size_t i, j;
	unsigned char t;

	for (i = 0, j = l - 1; i < j; i++, j--) {
		t = s[i];
		s[i] = s[j];
		s[j] = t;
	}
}

#define icarus_open2(devpath, baud, purge)  serial_open(devpath, baud, ICARUS_READ_FAULT_DECISECONDS, purge)
#define icarus_open(devpath, baud)  icarus_open2(devpath, baud, false)

int icarus_gets(unsigned char *buf, int fd, struct timeval *tv_finish, struct thr_info *thr, int read_count, int read_size)
{
	ssize_t ret = 0;
	int rc = 0;
	int epollfd = -1;
	int epoll_timeout = ICARUS_READ_FAULT_DECISECONDS * 100;
	int read_amount = read_size;
	bool first = true;

#ifdef HAVE_EPOLL
	struct epoll_event ev = {
		.events = EPOLLIN,
		.data.fd = fd,
	};
	struct epoll_event evr[2];
	if (thr && thr->work_restart_notifier[1] != -1) {
	epollfd = epoll_create(2);
	if (epollfd != -1) {
		if (-1 == epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev)) {
			close(epollfd);
			epollfd = -1;
		}
		{
			ev.data.fd = thr->work_restart_notifier[0];
			if (-1 == epoll_ctl(epollfd, EPOLL_CTL_ADD, thr->work_restart_notifier[0], &ev))
				applog(LOG_ERR, "%s: Error adding work restart fd to epoll", __func__);
			else
			{
				epoll_timeout *= read_count;
				read_count = 1;
			}
		}
	}
	else
		applog(LOG_ERR, "%s: Error creating epoll", __func__);
	}
#endif

	// Read reply 1 byte at a time to get earliest tv_finish
	while (true) {
#ifdef HAVE_EPOLL
		if (epollfd != -1 && (ret = epoll_wait(epollfd, evr, 2, epoll_timeout)) != -1)
		{
			if (ret == 1 && evr[0].data.fd == fd)
				ret = read(fd, buf, 1);
			else
			{
				if (ret)
					notifier_read(thr->work_restart_notifier);
				ret = 0;
			}
		}
		else
#endif
		//DUALMINER HACKING - read 4 at a time
		//ret = read(fd, buf, 1);
		ret = read(fd, buf, 4);

		if (ret < 0)
			return ICA_GETS_ERROR;

		if (first)
			cgtime(tv_finish);

		if (ret >= read_amount)
		{
			if (epollfd != -1)
				close(epollfd);

			char *hbuf = (char *)buf;
			print_hex(hbuf, read_size, "Read from UART:\n"); //DUALMINER

			return ICA_GETS_OK;
		}

		if (ret > 0) {
			buf += ret;
			read_amount -= ret;
			first = false;
			continue;
		}
			
		if (thr && thr->work_restart) {
			if (epollfd != -1)
				close(epollfd);
			applog(LOG_DEBUG, "%s: Interrupted by work restart", __func__);
			return ICA_GETS_RESTART;
		}

		rc++;
		if (rc >= read_count) {
			if (epollfd != -1)
				close(epollfd);
			applog(LOG_DEBUG, "%s: No data in %.2f seconds",
			       __func__,
			       (float)rc * epoll_timeout / 1000.);
			return ICA_GETS_TIMEOUT;
		}
	}
}

int icarus_write(int fd, const void *buf, size_t bufLen)
{
	size_t ret;

	print_hex((char*)buf, bufLen,"Send to UART:\n"); //DUALMINER

	if (unlikely(fd == -1))
		return 1;
	
	ret = write(fd, buf, bufLen);
	if (unlikely(ret != bufLen))
		return 1;

	return 0;
}

#define icarus_close(fd) serial_close(fd)

static void do_icarus_close(struct thr_info *thr)
{
	struct cgpu_info *icarus = thr->cgpu;
	const int fd = icarus->device_fd;
	if (fd == -1)
		return;
	icarus_close(fd);
	icarus->device_fd = -1;
}

static const char *timing_mode_str(enum timing_mode timing_mode)
{
	switch(timing_mode) {
	case MODE_DEFAULT:
		return MODE_DEFAULT_STR;
	case MODE_SHORT:
		return MODE_SHORT_STR;
	case MODE_LONG:
		return MODE_LONG_STR;
	case MODE_VALUE:
		return MODE_VALUE_STR;
	default:
		return MODE_UNKNOWN_STR;
	}
}

static
const char *icarus_set_timing(struct cgpu_info * const proc, const char * const optname, const char * const buf, char * const replybuf, enum bfg_set_device_replytype * const out_success)
{
	struct ICARUS_INFO * const info = proc->device_data;
	double Hs;
	char *eq;

	if (strcasecmp(buf, MODE_SHORT_STR) == 0) {
		// short
		info->read_count = ICARUS_READ_COUNT_TIMING;
		info->read_count_limit = 0;  // 0 = no limit

		info->timing_mode = MODE_SHORT;
		info->do_icarus_timing = true;
	} else if (strncasecmp(buf, MODE_SHORT_STREQ, strlen(MODE_SHORT_STREQ)) == 0) {
		// short=limit
		info->read_count = ICARUS_READ_COUNT_TIMING;

		info->timing_mode = MODE_SHORT;
		info->do_icarus_timing = true;

		info->read_count_limit = atoi(&buf[strlen(MODE_SHORT_STREQ)]);
		if (info->read_count_limit < 0)
			info->read_count_limit = 0;
		if (info->read_count_limit > ICARUS_READ_COUNT_LIMIT_MAX)
			info->read_count_limit = ICARUS_READ_COUNT_LIMIT_MAX;
	} else if (strcasecmp(buf, MODE_LONG_STR) == 0) {
		// long
		info->read_count = ICARUS_READ_COUNT_TIMING;
		info->read_count_limit = 0;  // 0 = no limit

		info->timing_mode = MODE_LONG;
		info->do_icarus_timing = true;
	} else if (strncasecmp(buf, MODE_LONG_STREQ, strlen(MODE_LONG_STREQ)) == 0) {
		// long=limit
		info->read_count = ICARUS_READ_COUNT_TIMING;

		info->timing_mode = MODE_LONG;
		info->do_icarus_timing = true;

		info->read_count_limit = atoi(&buf[strlen(MODE_LONG_STREQ)]);
		if (info->read_count_limit < 0)
			info->read_count_limit = 0;
		if (info->read_count_limit > ICARUS_READ_COUNT_LIMIT_MAX)
			info->read_count_limit = ICARUS_READ_COUNT_LIMIT_MAX;
	} else if ((Hs = atof(buf)) != 0) {
		// ns[=read_count]
		info->Hs = Hs / NANOSEC;
		info->fullnonce = info->Hs * (((double)0xffffffff) + 1);

		info->read_count = 0;
		if ((eq = strchr(buf, '=')) != NULL)
			info->read_count = atoi(eq+1);

		if (info->read_count < 1)
			info->read_count = (int)(info->fullnonce * TIME_FACTOR) - 1;

		if (unlikely(info->read_count < 1))
			info->read_count = 1;

		info->read_count_limit = 0;  // 0 = no limit
		
		info->timing_mode = MODE_VALUE;
		info->do_icarus_timing = false;
	} else {
		// Anything else in buf just uses DEFAULT mode

		info->fullnonce = info->Hs * (((double)0xffffffff) + 1);

		info->read_count = 0;
		if ((eq = strchr(buf, '=')) != NULL)
			info->read_count = atoi(eq+1);

		int def_read_count = ICARUS_READ_COUNT_TIMING;

		if (info->timing_mode == MODE_DEFAULT) {
			if (proc->drv == &icarus_drv) {
				info->do_default_detection = 0x10;
			} else {
				def_read_count = (int)(info->fullnonce * TIME_FACTOR) - 1;
			}

			info->do_icarus_timing = false;
		}
		if (info->read_count < 1)
			info->read_count = def_read_count;
		
		info->read_count_limit = 0;  // 0 = no limit
	}

	info->min_data_count = MIN_DATA_COUNT;

	info->read_count += 30; //DUALMINER HACKING

	applog(LOG_DEBUG, "%"PRIpreprv": Init: mode=%s read_count=%d limit=%dms Hs=%e",
		proc->proc_repr,
		timing_mode_str(info->timing_mode),
		info->read_count, info->read_count_limit, info->Hs);
	
	return NULL;
}

static uint32_t mask(int work_division)
{
	uint32_t nonce_mask = 0x7fffffff;

	// yes we can calculate these, but this way it's easy to see what they are
	switch (work_division) {
	case 1:
		nonce_mask = 0xffffffff;
		break;
	case 2:
		nonce_mask = 0x7fffffff;
		break;
	case 4:
		nonce_mask = 0x3fffffff;
		break;
	case 8:
		nonce_mask = 0x1fffffff;
		break;
	default:
		quit(1, "Invalid2 work_division (%d) must be 1, 2, 4 or 8", work_division);
	}

	return nonce_mask;
}

// Number of bytes remaining after reading a nonce from Icarus
int icarus_excess_nonce_size(int fd, struct ICARUS_INFO *info)
{
	// How big a buffer?
	int excess_size = info->read_size - ICARUS_NONCE_SIZE;

	// Try to read one more to ensure the device doesn't return
	// more than we want for this driver
	excess_size++;

	unsigned char excess_bin[excess_size];
	// Read excess_size from Icarus
	struct timeval tv_now;
	timer_set_now(&tv_now);
	//icarus_gets(excess_bin, fd, &tv_now, NULL, 1, excess_size);
	int bytes_read = read(fd, excess_bin, excess_size);
	// Number of bytes that were still available

	return bytes_read;
}

bool icarus_detect_custom(const char *devpath, struct device_drv *api, struct ICARUS_INFO *info)
{
	struct timeval tv_start, tv_finish;
	int fd;

	// Block 171874 nonce = (0xa2870100) = 0x000187a2
	// N.B. golden_ob MUST take less time to calculate
	//	than the timeout set in icarus_open()
	//	This one takes ~0.53ms on Rev3 Icarus
	const char golden_ob[] =
		"4679ba4ec99876bf4bfe086082b40025"
		"4df6c356451471139a3afa71e48f544a"
		"00000000000000000000000000000000"
		"0000000087320b1a1426674f2fa722ce";
	/* NOTE: This gets sent to basically every port specified in --scan-serial,
	 *       even ones that aren't Icarus; be sure they can all handle it, when
	 *       this is changed...
	 *       BitForce: Ignores entirely
	 *       ModMiner: Starts (useless) work, gets back to clean state
	 */

	const char golden_nonce[] = "000187a2";


	//BEGIN DUALMINER HACKING
	const char golden_scryptob[] ="55aa1f00000000000000000000000000000000000000000000000000aaaaaaaa711c0000603ebdb6e35b05223c54f8155ac33123006b4192e7aafafbeb9ef6544d2973d700000002069b9f9e3ce8a6778dea3d7a00926cd6eaa9585502c9b83a5601f198d7fbf09be9559d6335ebad363e4f147a8d9934006963030b4e54c408c837ebc2eeac129852a55fee1b1d88f6000c050000000600";
	const char golden_scryptnonce[] = "00050cdd";
	const uint32_t golden_scryptnonce_val = 0x00050cdd;

	char *dualnonce;
	unsigned char my_bin[52],scrypt_bin[160];
	int i = 2;    //0x000187a2 - 0x000187a0
	//END DUALMINER HACKING


	unsigned char ob_bin[64], nonce_bin[ICARUS_NONCE_SIZE];
	char nonce_hex[(sizeof(nonce_bin) * 2) + 1];

	drv_set_defaults(api, icarus_set_device_funcs, info, devpath, detectone_meta_info.serial, 1);

	int baud = info->baud;
	int work_division = info->work_division;
	int fpga_count = info->fpga_count;

	applog(LOG_DEBUG, "%s: Attempting to open %s", api->dname, devpath);

	fd = icarus_open2(devpath, baud, true);
	if (unlikely(fd == -1)) {
		applog(LOG_DEBUG, "%s: Failed to open %s", api->dname, devpath);
		return false;
	}
	
	// Set a default so that individual drivers need not specify
	// e.g. Cairnsmore
	if (info->read_size == 0)
		info->read_size = ICARUS_DEFAULT_READ_SIZE;


	//BEGIN DUALMINER HACKING

	//original code:
	//hex2bin(ob_bin, golden_ob, sizeof(ob_bin));
	//icarus_write(fd, ob_bin, sizeof(ob_bin));

	dual_reset(fd);
	// initialize
	opt_ltconly ? opt_ltc_only_init(fd) : dualminer_init(fd);

	usleep(1000);

	if(opt_scrypt)
	{
		memset(scrypt_bin, 0, sizeof(scrypt_bin));
		hex2bin(scrypt_bin, golden_scryptob, sizeof(scrypt_bin));
		icarus_write(fd, scrypt_bin, sizeof(scrypt_bin));
		dualnonce=(char *)golden_scryptnonce;
	}
	else
	{
		open_btc_unit_single(fd, i);
		applog(LOG_DEBUG,"dualminer Detect: test btc mode\n");
		// send test work data
		hex2bin(ob_bin, golden_ob, sizeof(ob_bin));
		memset(my_bin, 0, sizeof(my_bin));
		my_bin[0] = 0x55;
		my_bin[1] = 0xaa;
		my_bin[2] = 0x0f;
		my_bin[4] = 0xa0 + 2 - i;
		my_bin[5] = 0x87;
		my_bin[6] = 0x01;
		memcpy(my_bin + 8, ob_bin, 32);
		memcpy(my_bin + 40, ob_bin + 52, 12);
		rev(my_bin+8, 32);
		rev(my_bin+40, 12);
		icarus_write(fd, my_bin, sizeof(my_bin));
		dualnonce=(char *)golden_nonce;
	}



	//END DUALMINER HACKING

	cgtime(&tv_start);

	memset(nonce_bin, 0, sizeof(nonce_bin));
	// Do not use info->read_size here, instead read exactly ICARUS_NONCE_SIZE
	// We will then compare the bytes left in fd with info->read_size to determine
	// if this is a valid device
	icarus_gets(nonce_bin, fd, &tv_finish, NULL, 1, ICARUS_NONCE_SIZE);


	rev(nonce_bin, 4); //DUAMINER HACKING


	
	// How many bytes were left after reading the above nonce
	int bytes_left = icarus_excess_nonce_size(fd, info);


	//DUALMINER HACKING - leave fd open, store in ->device_fd
	//icarus_close(fd);


	bin2hex(nonce_hex, nonce_bin, sizeof(nonce_bin));






	//DUALMINER HACKING - test dualnone, not golden_nonce
	//if (strncmp(nonce_hex, golden_nonce, 8)) {
	if (strncmp(nonce_hex, dualnonce, 8)) {

		applog(LOG_DEBUG,
			"%s: "
			"Test failed at %s: get %s, should: %s",
			api->dname,
			devpath, nonce_hex, dualnonce);


		//BEGIN DUALMINER HACKING
		icarus_close(fd);

#ifndef WIN32
		char cmd[128];
		sprintf(cmd,"sudo chmod 660 %s",devpath);
		system(cmd);
#endif
		//END DUALMINER HACKING


		return false;
	}

	if (info->read_size - ICARUS_NONCE_SIZE != bytes_left)
	{
		applog(LOG_DEBUG,
			   "%s: "
			   "Test failed at %s: expected %d bytes, got %d",
			   api->dname,
			   devpath, info->read_size, ICARUS_NONCE_SIZE + bytes_left);


		//BEGIN DUALMINER HACKING
		icarus_close(fd);

#ifndef WIN32
		char cmd[128];
		sprintf(cmd,"sudo chmod 660 %s",devpath);
		system(cmd);
#endif
		//END DUALMINER HACKING


		return false;
	}
	
	applog(LOG_DEBUG,
		"%s: "
		"Test succeeded at %s: got %s",
	       api->dname,
			devpath, nonce_hex);

	if (serial_claim_v(devpath, api))
		return false;



	//BEGIN DUALMINER HACKING


	if(opt_dualminer_test || opt_scrypt)
	{
		set_rts_status(fd, RTS_HIGH);
	}


	if(opt_scrypt)
	{
		applog(LOG_NOTICE, "Detected LTC UART: %s", devpath);
	}
	else
	{
		applog(LOG_NOTICE, "Detected BTC UART: %s", devpath);
	}

	//enable btc clock gating according --btc
	//	open_btc_unit(fd, opt_dualminer_btc_gating);
	if(!opt_dualminer_test)
	{
		gc3355_init(fd, opt_dualminer_pll, opt_dualminer_btc_gating, opt_ltconly);
	}


	//END DUALMINER HACKING




	/* We have a real Icarus! */
	struct cgpu_info *icarus;
	icarus = calloc(1, sizeof(struct cgpu_info));
	icarus->drv = api;
	icarus->device_path = strdup(devpath);

	//DUALMINER HACKING - leave fd open, store in ->device_fd
	//icarus->device_fd = -1;
	icarus->device_fd = fd;

	icarus->threads = 1;
	icarus->set_device_funcs = icarus_set_device_funcs;
	add_cgpu(icarus);

	applog(LOG_INFO, "Found %"PRIpreprv" at %s",
		icarus->proc_repr,
		devpath);

	//DUALMINER HACKING
//	applog(LOG_DEBUG, "%"PRIpreprv": Init: baud=%d work_division=%d fpga_count=%d",
//		icarus->proc_repr,
//		baud, work_division, fpga_count);

	if(opt_scrypt) info->prev_hashrate=(double)((50000)*(double)opt_pll_freq)/600;
	else info->prev_hashrate=((double)opt_btc_number*1000000000/160)*(double)opt_pll_freq/400;

	applog(LOG_DEBUG, "dualminer: Init: pll=%d, btcnum=%d, hashrate=%d",opt_pll_freq,opt_btc_number,info->prev_hashrate);

	//END

	icarus->device_data = info;

	timersub(&tv_finish, &tv_start, &(info->golden_tv));
	icarus_set_timing(icarus, NULL, "", NULL, NULL);

	return true;
}

static bool icarus_detect_one(const char *devpath)
{
	struct ICARUS_INFO *info = calloc(1, sizeof(struct ICARUS_INFO));
	if (unlikely(!info))
		quit(1, "Failed to malloc ICARUS_INFO");

	// TODO: try some higher speeds with the Icarus and BFL to see
	// if they support them and if setting them makes any difference
	// N.B. B3000000 doesn't work on Icarus
	info->baud = ICARUS_IO_SPEED;
	info->reopen_mode = IRM_TIMEOUT;
	info->Hs = ICARUS_REV3_HASH_TIME;
	info->timing_mode = MODE_DEFAULT;
	info->read_size = ICARUS_DEFAULT_READ_SIZE;

	//DUALMINER
	info->work_division = 2;
	info->fpga_count = 2;
	//END

	if (!icarus_detect_custom(devpath, &icarus_drv, info)) {
		free(info);
		return false;
	}
	return true;
}

static
bool icarus_lowl_probe(const struct lowlevel_device_info * const info)
{
	return vcom_lowl_probe_wrapper(info, icarus_detect_one);
}

static bool icarus_prepare(struct thr_info *thr)
{
	struct cgpu_info *icarus = thr->cgpu;
	struct ICARUS_INFO *info = icarus->device_data;

	//DUALMINER HACKING

	//original code:
	//icarus->device_fd = -1;
	//int fd = icarus_open2(icarus->device_path, info->baud, true);

	int fd=0;
	if(icarus->device_fd >0)
	{
		fd = icarus->device_fd;
	}
	else
	{
		fd = icarus_open(icarus->device_path, info[icarus->device_id].baud);
	}
	usleep(1000);

	//END HACKING

	if (unlikely(-1 == fd)) {
		applog(LOG_ERR, "%s: Failed to open %s",
		       icarus->dev_repr,
		       icarus->device_path);
		return false;
	}

	icarus->device_fd = fd;

	applog(LOG_INFO, "%s: Opened %s", icarus->dev_repr, icarus->device_path);

	struct icarus_state *state;
	thr->cgpu_data = state = calloc(1, sizeof(*state));
	state->firstrun = true;

#ifdef HAVE_EPOLL
	int epollfd = epoll_create(2);
	if (epollfd != -1)
	{
		close(epollfd);
		notifier_init(thr->work_restart_notifier);
	}
#endif

	icarus->status = LIFE_INIT2;
	
	return true;
}

static bool icarus_init(struct thr_info *thr)
{
	struct cgpu_info *icarus = thr->cgpu;
	struct ICARUS_INFO *info = icarus->device_data;
	int fd = icarus->device_fd;
	
	if (!info->work_division)
	{
		struct timeval tv_finish;
		
		// For reading the nonce from Icarus
		unsigned char res_bin[info->read_size];
		// For storing the the 32-bit nonce
		uint32_t res;
		
		applog(LOG_DEBUG, "%"PRIpreprv": Work division not specified - autodetecting", icarus->proc_repr);
		
		// Special packet to probe work_division
		unsigned char pkt[64] =
			"\x2e\x4c\x8f\x91\xfd\x59\x5d\x2d\x7e\xa2\x0a\xaa\xcb\x64\xa2\xa0"
			"\x43\x82\x86\x02\x77\xcf\x26\xb6\xa1\xee\x04\xc5\x6a\x5b\x50\x4a"
			"BFGMiner Probe\0\0"
			"BFG\0\x64\x61\x01\x1a\xc9\x06\xa9\x51\xfb\x9b\x3c\x73";
		
		icarus_write(fd, pkt, sizeof(pkt));
		memset(res_bin, 0, sizeof(res_bin));
		if (ICA_GETS_OK == icarus_gets(res_bin, fd, &tv_finish, NULL, info->read_count, info->read_size))
		{
			memcpy(&res, res_bin, sizeof(res));
			res = be32toh(res);
		}
		else
			res = 0;
		
		switch (res) {
			case 0x04C0FDB4:
				info->work_division = 1;
				break;
			case 0x82540E46:
				info->work_division = 2;
				break;
			case 0x417C0F36:
				info->work_division = 4;
				break;
			case 0x60C994D5:
				info->work_division = 8;
				break;
			default:
				applog(LOG_ERR, "%"PRIpreprv": Work division autodetection failed (assuming 2): got %08x", icarus->proc_repr, res);
				info->work_division = 2;
		}
		applog(LOG_DEBUG, "%"PRIpreprv": Work division autodetection got %08x (=%d)", icarus->proc_repr, res, info->work_division);
	}
	
	if (!info->fpga_count)
		info->fpga_count = info->work_division;
	
	info->nonce_mask = mask(info->work_division);
	
	return true;
}

static bool icarus_reopen(struct cgpu_info *icarus, struct icarus_state *state, int *fdp)
{
	struct ICARUS_INFO *info = icarus->device_data;

	// Reopen the serial port to workaround a USB-host-chipset-specific issue with the Icarus's buggy USB-UART
	do_icarus_close(icarus->thr[0]);
	*fdp = icarus->device_fd = icarus_open(icarus->device_path, info->baud);
	if (unlikely(-1 == *fdp)) {
		applog(LOG_ERR, "%"PRIpreprv": Failed to reopen on %s", icarus->proc_repr, icarus->device_path);
		dev_error(icarus, REASON_DEV_COMMS_ERROR);
		state->firstrun = true;
		return false;
	}
	return true;
}

static
bool icarus_job_prepare(struct thr_info *thr, struct work *work, __maybe_unused uint64_t max_nonce)
{
	struct cgpu_info * const icarus = thr->cgpu;
	struct icarus_state * const state = thr->cgpu_data;


	//BEGIN DUALMINER HACKING

	//old code:
	//uint8_t * const ob_bin = state->ob_bin;
	//
	//memcpy(ob_bin, work->midstate, 32);
	//memcpy(ob_bin + 52, work->data + 64, 12);
	//if (!(memcmp(&ob_bin[56], "\xff\xff\xff\xff", 4)
	//   || memcmp(&ob_bin, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 32))) {
	//	// This sequence is used on cairnsmore bitstreams for commands, NEVER send it otherwise
	//	applog(LOG_WARNING, "%"PRIpreprv": Received job attempting to send a command, corrupting it!",
	//	       icarus->proc_repr);
	//	ob_bin[56] = 0;
	//}
	//rev(ob_bin, 32);
	//rev(ob_bin + 52, 12);


	if(opt_scrypt)
	{
		//int fd = icarus->device_fd;
		memset(state->scrypt_bin, 0, 160);
		state->scrypt_bin[0] = 0x55;
		state->scrypt_bin[1] = 0xaa;

		state->scrypt_bin[2] = 0x1f;
		state->scrypt_bin[3] = 0x00;

		print_hex(work->target, 32, "Scrypt target:\n");
		print_hex(work->midstate, 32, "Scrypt midstate:\n");
		print_hex(work->data, 80, "Scrypt data:\n");

		memcpy(state->scrypt_bin + 4, work->target, 32);
		memcpy(state->scrypt_bin + 36, work->midstate, 32);
		memcpy(state->scrypt_bin + 68, work->data, 80);
		state->scrypt_bin[148] = 0xff;
		state->scrypt_bin[149] = 0xff;
		state->scrypt_bin[150] = 0xff;
		state->scrypt_bin[151] = 0xff;
	}
	else
	{
		memset(state->ob_bin, 0, 64);
		memcpy(state->ob_bin, work->midstate, 32);
		memcpy(state->ob_bin+52, work->data+64, 12);
		// Comment by LQX
		//rev(ob_bin, 32);
		//rev(ob_bin + 52, 12);

		/* Added by LQX */
		memset(state->my_bin, 0, 52);
		state->my_bin[0] = 0x55;
		state->my_bin[1] = 0xaa;
		state->my_bin[2] = 0x0f;
		state->my_bin[3] = 0x00;
		memcpy(state->my_bin + 8, state->ob_bin, 32);
		memcpy(state->my_bin + 40, state->ob_bin+52, 12);
	}


	//END HACKING

	return true;
}

static bool icarus_job_start(struct thr_info *thr)
{
	struct cgpu_info *icarus = thr->cgpu;
	struct ICARUS_INFO *info = icarus->device_data;
	struct icarus_state *state = thr->cgpu_data;
	const uint8_t * ob_bin; //DUALMINER HACKING
	int fd = icarus->device_fd;
	int ret;

	//DUALMINER
	if (opt_scrypt)
	{
		if(opt_ltconly)
		{
			opt_scrypt_init(fd);
		}
		else
		{
			dualminer_init(fd);
		}
	}
	//END



	// Handle dynamic clocking for "subclass" devices
	// This needs to run before sending next job, since it hashes the command too
	if (info->dclk.freqM && likely(!state->firstrun)) {
		dclk_preUpdate(&info->dclk);
		dclk_updateFreq(&info->dclk, info->dclk_change_clock_func, thr);
	}
	
	cgtime(&state->tv_workstart);

	//DUALMINER HACKING

	//old code:
	//ret = icarus_write(fd, ob_bin, 64);

	int bin_size;

	if(opt_scrypt)
	{
		ob_bin = state->scrypt_bin;
		bin_size = 160;
		ret = icarus_write(fd, ob_bin, bin_size);
	}
	else
	{
		ob_bin = state->my_bin;
		bin_size = 52;
		ret = icarus_write(fd, ob_bin, bin_size);
	}

	//END


	if (ret) {
		do_icarus_close(thr);
		applog(LOG_ERR, "%"PRIpreprv": Comms error (werr=%d)", icarus->proc_repr, ret);
		dev_error(icarus, REASON_DEV_COMMS_ERROR);
		return false;	/* This should never happen */
	}

	usleep(2000); //DUALMINER HACKING

	if (opt_debug) {
		char ob_hex[300];
		bin2hex(ob_hex, ob_bin, bin_size);
		applog(LOG_DEBUG, "%"PRIpreprv" sent: %s",
			icarus->proc_repr,
			ob_hex);
	}

	return true;
}

static
struct work *icarus_process_worknonce(struct icarus_state *state, uint32_t *nonce)
{
	*nonce = be32toh(*nonce);
	if (test_nonce(state->last_work, *nonce, false))
		return state->last_work;
	if (likely(state->last2_work && test_nonce(state->last2_work, *nonce, false)))
		return state->last2_work;
	return NULL;
}

static
void handle_identify(struct thr_info * const thr, int ret, const bool was_first_run)
{
	const struct cgpu_info * const icarus = thr->cgpu;
	const struct ICARUS_INFO * const info = icarus->device_data;
	struct icarus_state * const state = thr->cgpu_data;
	int fd = icarus->device_fd;
	struct timeval tv_now;
	double delapsed;
	
	// For reading the nonce from Icarus
	unsigned char nonce_bin[info->read_size];
	// For storing the the 32-bit nonce
	uint32_t nonce;
	
	if (fd == -1)
		return;
	
	// If identify is requested (block erupters):
	// 1. Don't start the next job right away (above)
	// 2. Wait for the current job to complete 100%
	
	if (!was_first_run)
	{
		applog(LOG_DEBUG, "%"PRIpreprv": Identify: Waiting for current job to finish", icarus->proc_repr);
		while (true)
		{
			cgtime(&tv_now);
			delapsed = tdiff(&tv_now, &state->tv_workstart);
			if (delapsed + 0.1 > info->fullnonce)
				break;
			
			// Try to get more nonces (ignoring work restart)
			memset(nonce_bin, 0, sizeof(nonce_bin));
			ret = icarus_gets(nonce_bin, fd, &tv_now, NULL, (info->fullnonce - delapsed) * 10, info->read_size);
			if (ret == ICA_GETS_OK)
			{
				memcpy(&nonce, nonce_bin, sizeof(nonce));
				nonce = be32toh(nonce);
				submit_nonce(thr, state->last_work, nonce);
			}
		}
	}
	else
		applog(LOG_DEBUG, "%"PRIpreprv": Identify: Current job should already be finished", icarus->proc_repr);
	
	// 3. Delay 3 more seconds
	applog(LOG_DEBUG, "%"PRIpreprv": Identify: Leaving idle for 3 seconds", icarus->proc_repr);
	cgsleep_ms(3000);
	
	// Check for work restart in the meantime
	if (thr->work_restart)
	{
		applog(LOG_DEBUG, "%"PRIpreprv": Identify: Work restart requested during delay", icarus->proc_repr);
		goto no_job_start;
	}
	
	// 4. Start next job
	if (!state->firstrun)
	{
		applog(LOG_DEBUG, "%"PRIpreprv": Identify: Starting next job", icarus->proc_repr);
		if (!icarus_job_start(thr))
no_job_start:
			state->firstrun = true;
	}
	
	state->identify = false;
}

static
void icarus_transition_work(struct icarus_state *state, struct work *work)
{
	if (state->last2_work)
		free_work(state->last2_work);
	state->last2_work = state->last_work;
	state->last_work = copy_work(work);
}

static int64_t icarus_scanhash(struct thr_info *thr, struct work *work,
				__maybe_unused int64_t max_nonce)
{
	struct cgpu_info *icarus;
	int fd;
	int ret;

	struct ICARUS_INFO *info;

	struct work *nonce_work;
	int64_t hash_count;
	struct timeval tv_start = {.tv_sec=0}, elapsed;
	struct timeval tv_history_start, tv_history_finish;
	double Ti, Xi;
	int i;
	bool was_hw_error = false;
	bool was_first_run;

	struct ICARUS_HISTORY *history0, *history;
	int count;
	double Hs, W, fullnonce;
	int read_count;
	bool limited;
	int64_t estimate_hashes;
	uint32_t values;
	int64_t hash_count_range;

	elapsed.tv_sec = elapsed.tv_usec = 0;

	icarus = thr->cgpu;
	struct icarus_state *state = thr->cgpu_data;
	was_first_run = state->firstrun;

	icarus_job_prepare(thr, work, max_nonce);

	// Wait for the previous run's result
	fd = icarus->device_fd;
	info = icarus->device_data;
	
	// For reading the nonce from Icarus
	unsigned char nonce_bin[info->read_size];
	// For storing the the 32-bit nonce
	uint32_t nonce;

	if (unlikely(fd == -1) && !icarus_reopen(icarus, state, &fd))
		return -1;
	
	if (!state->firstrun) {
		if (state->changework)
		{
			state->changework = false;
			ret = ICA_GETS_RESTART;
		}
		else
		{
			read_count = info->read_count;
keepwaiting:
			/* Icarus will return info->read_size bytes nonces or nothing */
			memset(nonce_bin, 0, sizeof(nonce_bin));

			//DUALMINER HACKING
			if (opt_scrypt)
			{
				read_count = 48;
			}
			else
			{
				read_count = 16;
			}
			//

			ret = icarus_gets(nonce_bin, fd, &state->tv_workfinish, thr, read_count, info->read_size);

			switch (ret) {
				case ICA_GETS_RESTART:
					// The prepared work is invalid, and the current work is abandoned
					// Go back to the main loop to get the next work, and stuff
					// Returning to the main loop will clear work_restart, so use a flag...
					state->changework = true;
					return 0;
				case ICA_GETS_ERROR:
					do_icarus_close(thr);
					applog(LOG_ERR, "%"PRIpreprv": Comms error (rerr)", icarus->proc_repr);
					dev_error(icarus, REASON_DEV_COMMS_ERROR);
					if (!icarus_reopen(icarus, state, &fd))
						return -1;
					break;
				case ICA_GETS_TIMEOUT:
					if (info->reopen_mode == IRM_TIMEOUT && !icarus_reopen(icarus, state, &fd))
						return -1;
				case ICA_GETS_OK:
					break;
			}


			//DUALMINER HACKING
			rev(nonce_bin, 4);
			//END

		}

		tv_start = state->tv_workstart;
		timersub(&state->tv_workfinish, &tv_start, &elapsed);
	}
	else
	{
		if (fd == -1 && !icarus_reopen(icarus, state, &fd))
			return -1;
		
		// First run; no nonce, no hashes done
		ret = ICA_GETS_ERROR;
	}

#ifndef WIN32
	tcflush(fd, TCOFLUSH);
#endif

	if (ret == ICA_GETS_OK)
	{
		memcpy(&nonce, nonce_bin, sizeof(nonce));
		nonce_work = icarus_process_worknonce(state, &nonce);
		if (likely(nonce_work))
		{
			if (nonce_work == state->last2_work)
			{
				// nonce was for the last job; submit and keep processing the current one
				submit_nonce(thr, nonce_work, nonce);
				goto keepwaiting;
			}
			if (info->continue_search)
			{
				read_count = info->read_count - ((timer_elapsed_us(&state->tv_workstart, NULL) / (1000000 / TIME_FACTOR)) + 1);
				if (read_count)
				{
					submit_nonce(thr, nonce_work, nonce);
					goto keepwaiting;
				}
			}
		}
		else
			was_hw_error = true;
	}
	
	// Handle dynamic clocking for "subclass" devices
	// This needs to run before sending next job, since it hashes the command too
	if (info->dclk.freqM && likely(ret == ICA_GETS_OK || ret == ICA_GETS_TIMEOUT)) {
		int qsec = ((4 * elapsed.tv_sec) + (elapsed.tv_usec / 250000)) ?: 1;
		for (int n = qsec; n; --n)
			dclk_gotNonces(&info->dclk);
		if (was_hw_error)
			dclk_errorCount(&info->dclk, qsec);
	}
	
	// Force a USB close/reopen on any hw error (or on request, eg for baud change)
	if (was_hw_error || info->reopen_now)
	{
		info->reopen_now = false;
		if (info->reopen_mode == IRM_CYCLE)
		{}  // Do nothing here, we reopen after sending the job
		else
		if (!icarus_reopen(icarus, state, &fd))
			state->firstrun = true;
	}

	if (unlikely(state->identify))
	{
		// Delay job start until later...
	}
	else
	if (unlikely(icarus->deven != DEV_ENABLED || !icarus_job_start(thr)))
		state->firstrun = true;

	if (info->reopen_mode == IRM_CYCLE && !icarus_reopen(icarus, state, &fd))
		state->firstrun = true;

	work->blk.nonce = 0xffffffff;

	if (ret == ICA_GETS_ERROR) {
		state->firstrun = false;
		icarus_transition_work(state, work);
		hash_count = 0;
		goto out;
	}

	// OK, done starting Icarus's next job... now process the last run's result!

	// aborted before becoming idle, get new work
	if (ret == ICA_GETS_TIMEOUT || ret == ICA_GETS_RESTART) {
		icarus_transition_work(state, work);
		// ONLY up to just when it aborted
		// We didn't read a reply so we don't subtract ICARUS_READ_TIME

		//DUALMINER HACKING
		//original code:
		//estimate_hashes = ((double)(elapsed.tv_sec)
		//			+ ((double)(elapsed.tv_usec))/((double)1000000)) / info->Hs;

		applog(LOG_DEBUG, "dualminer hashrate=%d", info->prev_hashrate);
		estimate_hashes = ((double)(elapsed.tv_sec) + ((double)(elapsed.tv_usec))/((double)1000000))*info->prev_hashrate;

		//END HACKING



		// If some Serial-USB delay allowed the full nonce range to
		// complete it can't have done more than a full nonce
		if (unlikely(estimate_hashes > 0xffffffff))
			estimate_hashes = 0xffffffff;

		applog(LOG_DEBUG, "%"PRIpreprv" no nonce = 0x%08"PRIx64" hashes (%"PRId64".%06lus)",
		       icarus->proc_repr,
		       (uint64_t)estimate_hashes,
		       (int64_t)elapsed.tv_sec, (unsigned long)elapsed.tv_usec);

		hash_count = estimate_hashes;
		goto out;
	}

	// Only ICA_GETS_OK gets here
	
	if (likely(!was_hw_error))
		submit_nonce(thr, nonce_work, nonce);
	else
		inc_hw_errors(thr, state->last_work, nonce);
	icarus_transition_work(state, work);

	//DUALMINER HACKING

	//original code:
	//hash_count = (nonce & info->nonce_mask);
	//hash_count++;
	//hash_count *= info->fpga_count;

	if (!was_hw_error)
	{
		//do_dualminer_close(thr);
		hash_count = opt_scrypt?nonce:((double)(((double)nonce)*opt_btc_number)/160);
		info->prev_hashrate=(double)hash_count/((double)(elapsed.tv_sec) + ((double)(elapsed.tv_usec))/((double)1000000));
		applog(LOG_DEBUG, "dualminer hashcount = %d, hashrate=%d, opt_btc_number=%d", hash_count, info->prev_hashrate, opt_btc_number);

	}
	else
	{
		hash_count = ((double)(elapsed.tv_sec) + ((double)(elapsed.tv_usec))/((double)1000000))*info->prev_hashrate;
	}

	//	hash_count = (nonce & info->nonce_mask);
	//	hash_count++;
	//	hash_count *= info->fpga_count;



	//END


	applog(LOG_DEBUG, "%"PRIpreprv" nonce = 0x%08x = 0x%08" PRIx64 " hashes (%"PRId64".%06lus)",
	       icarus->proc_repr,
	       nonce,
	       (uint64_t)hash_count,
	       (int64_t)elapsed.tv_sec, (unsigned long)elapsed.tv_usec);

	if (info->do_default_detection && elapsed.tv_sec >= DEFAULT_DETECT_THRESHOLD) {
		int MHs = (double)hash_count / ((double)elapsed.tv_sec * 1e6 + (double)elapsed.tv_usec);
		--info->do_default_detection;
		applog(LOG_DEBUG, "%"PRIpreprv": Autodetect device speed: %d MH/s", icarus->proc_repr, MHs);
		if (MHs <= 370 || MHs > 420) {
			// Not a real Icarus: enable short timing
			applog(LOG_WARNING, "%"PRIpreprv": Seems too %s to be an Icarus; calibrating with short timing", icarus->proc_repr, MHs>380?"fast":"slow");
			info->timing_mode = MODE_SHORT;
			info->do_icarus_timing = true;
			info->do_default_detection = 0;
		}
		else
		if (MHs <= 380) {
			// Real Icarus?
			if (!info->do_default_detection) {
				applog(LOG_DEBUG, "%"PRIpreprv": Seems to be a real Icarus", icarus->proc_repr);
				info->read_count = (int)(info->fullnonce * TIME_FACTOR) - 1;
			}
		}
		else
		if (MHs <= 420) {
			// Enterpoint Cairnsmore1
			size_t old_repr_len = strlen(icarus->proc_repr);
			char old_repr[old_repr_len + 1];
			strcpy(old_repr, icarus->proc_repr);
			convert_icarus_to_cairnsmore(icarus);
			info->do_default_detection = 0;
			applog(LOG_WARNING, "%"PRIpreprv": Detected Cairnsmore1 device, upgrading driver to %"PRIpreprv, old_repr, icarus->proc_repr);
		}
	}

	// Ignore possible end condition values ... and hw errors
	// TODO: set limitations on calculated values depending on the device
	// to avoid crap values caused by CPU/Task Switching/Swapping/etc
	if (info->do_icarus_timing
	&&  !was_hw_error
	&&  ((nonce & info->nonce_mask) > END_CONDITION)
	&&  ((nonce & info->nonce_mask) < (info->nonce_mask & ~END_CONDITION))) {
		cgtime(&tv_history_start);

		history0 = &(info->history[0]);

		if (history0->values == 0)
			timeradd(&tv_start, &history_sec, &(history0->finish));

		Ti = (double)(elapsed.tv_sec)
			+ ((double)(elapsed.tv_usec))/((double)1000000)
			- ((double)ICARUS_READ_TIME(info->baud, info->read_size));
		Xi = (double)hash_count;
		history0->sumXiTi += Xi * Ti;
		history0->sumXi += Xi;
		history0->sumTi += Ti;
		history0->sumXi2 += Xi * Xi;

		history0->values++;

		if (history0->hash_count_max < hash_count)
			history0->hash_count_max = hash_count;
		if (history0->hash_count_min > hash_count || history0->hash_count_min == 0)
			history0->hash_count_min = hash_count;

		if (history0->values >= info->min_data_count
		&&  timercmp(&tv_start, &(history0->finish), >)) {
			for (i = INFO_HISTORY; i > 0; i--)
				memcpy(&(info->history[i]),
					&(info->history[i-1]),
					sizeof(struct ICARUS_HISTORY));

			// Initialise history0 to zero for summary calculation
			memset(history0, 0, sizeof(struct ICARUS_HISTORY));

			// We just completed a history data set
			// So now recalc read_count based on the whole history thus we will
			// initially get more accurate until it completes INFO_HISTORY
			// total data sets
			count = 0;
			for (i = 1 ; i <= INFO_HISTORY; i++) {
				history = &(info->history[i]);
				if (history->values >= MIN_DATA_COUNT) {
					count++;

					history0->sumXiTi += history->sumXiTi;
					history0->sumXi += history->sumXi;
					history0->sumTi += history->sumTi;
					history0->sumXi2 += history->sumXi2;
					history0->values += history->values;

					if (history0->hash_count_max < history->hash_count_max)
						history0->hash_count_max = history->hash_count_max;
					if (history0->hash_count_min > history->hash_count_min || history0->hash_count_min == 0)
						history0->hash_count_min = history->hash_count_min;
				}
			}

			// All history data
			Hs = (history0->values*history0->sumXiTi - history0->sumXi*history0->sumTi)
				/ (history0->values*history0->sumXi2 - history0->sumXi*history0->sumXi);
			W = history0->sumTi/history0->values - Hs*history0->sumXi/history0->values;
			hash_count_range = history0->hash_count_max - history0->hash_count_min;
			values = history0->values;
			
			// Initialise history0 to zero for next data set
			memset(history0, 0, sizeof(struct ICARUS_HISTORY));

			fullnonce = W + Hs * (((double)0xffffffff) + 1);
			read_count = (int)(fullnonce * TIME_FACTOR) - 1;
			if (info->read_count_limit > 0 && read_count > info->read_count_limit) {
				read_count = info->read_count_limit;
				limited = true;
			} else
				limited = false;

			info->Hs = Hs;
			info->read_count = read_count;

			info->fullnonce = fullnonce;
			info->count = count;
			info->W = W;
			info->values = values;
			info->hash_count_range = hash_count_range;

			if (info->min_data_count < MAX_MIN_DATA_COUNT)
				info->min_data_count *= 2;
			else if (info->timing_mode == MODE_SHORT)
				info->do_icarus_timing = false;

//			applog(LOG_DEBUG, "%"PRIpreprv" Re-estimate: read_count=%d%s fullnonce=%fs history count=%d Hs=%e W=%e values=%d hash range=0x%08lx min data count=%u", icarus->proc_repr, read_count, limited ? " (limited)" : "", fullnonce, count, Hs, W, values, hash_count_range, info->min_data_count);
			applog(LOG_DEBUG, "%"PRIpreprv" Re-estimate: Hs=%e W=%e read_count=%d%s fullnonce=%.3fs",
					icarus->proc_repr,
					Hs, W, read_count,
					limited ? " (limited)" : "", fullnonce);
		}
		info->history_count++;
		cgtime(&tv_history_finish);

		timersub(&tv_history_finish, &tv_history_start, &tv_history_finish);
		timeradd(&tv_history_finish, &(info->history_time), &(info->history_time));
	}

out:
	if (unlikely(state->identify))
		handle_identify(thr, ret, was_first_run);
	
	return hash_count;
}

static struct api_data *icarus_drv_stats(struct cgpu_info *cgpu)
{
	struct api_data *root = NULL;
	struct ICARUS_INFO *info = cgpu->device_data;

	// Warning, access to these is not locked - but we don't really
	// care since hashing performance is way more important than
	// locking access to displaying API debug 'stats'
	// If locking becomes an issue for any of them, use copy_data=true also
	root = api_add_int(root, "read_count", &(info->read_count), false);
	root = api_add_int(root, "read_count_limit", &(info->read_count_limit), false);
	root = api_add_double(root, "fullnonce", &(info->fullnonce), false);
	root = api_add_int(root, "count", &(info->count), false);
	root = api_add_hs(root, "Hs", &(info->Hs), false);
	root = api_add_double(root, "W", &(info->W), false);
	root = api_add_uint(root, "total_values", &(info->values), false);
	root = api_add_uint64(root, "range", &(info->hash_count_range), false);
	root = api_add_uint64(root, "history_count", &(info->history_count), false);
	root = api_add_timeval(root, "history_time", &(info->history_time), false);
	root = api_add_uint(root, "min_data_count", &(info->min_data_count), false);
	root = api_add_uint(root, "timing_values", &(info->history[0].values), false);
	root = api_add_const(root, "timing_mode", timing_mode_str(info->timing_mode), false);
	root = api_add_bool(root, "is_timing", &(info->do_icarus_timing), false);
	root = api_add_int(root, "baud", &(info->baud), false);
	root = api_add_int(root, "work_division", &(info->work_division), false);
	root = api_add_int(root, "fpga_count", &(info->fpga_count), false);

	return root;
}

static
const char *icarus_set_baud(struct cgpu_info * const proc, const char * const optname, const char * const newvalue, char * const replybuf, enum bfg_set_device_replytype * const out_success)
{
	struct ICARUS_INFO * const info = proc->device_data;
	const int baud = atoi(newvalue);
	if (!valid_baud(baud))
		return "Invalid baud setting";
	if (info->baud != baud)
	{
		info->baud = baud;
		info->reopen_now = true;
	}
	return NULL;
}

static
const char *icarus_set_work_division(struct cgpu_info * const proc, const char * const optname, const char * const newvalue, char * const replybuf, enum bfg_set_device_replytype * const out_success)
{
	struct ICARUS_INFO * const info = proc->device_data;
	const int work_division = atoi(newvalue);
	if (!(work_division == 1 || work_division == 2 || work_division == 4 || work_division == 8))
		return "Invalid work_division: must be 1, 2, 4 or 8";
	if (info->user_set & IUS_FPGA_COUNT)
	{
		if (info->fpga_count > work_division)
			return "work_division must be >= fpga_count";
	}
	else
		info->fpga_count = work_division;
	info->user_set |= IUS_WORK_DIVISION;
	info->work_division = work_division;
	info->nonce_mask = mask(work_division);
	return NULL;
}

static
const char *icarus_set_fpga_count(struct cgpu_info * const proc, const char * const optname, const char * const newvalue, char * const replybuf, enum bfg_set_device_replytype * const out_success)
{
	struct ICARUS_INFO * const info = proc->device_data;
	const int fpga_count = atoi(newvalue);
	if (fpga_count < 1 || fpga_count > info->work_division)
		return "Invalid fpga_count: must be >0 and <=work_division";
	info->fpga_count = fpga_count;
	return NULL;
}

static
const char *icarus_set_reopen(struct cgpu_info * const proc, const char * const optname, const char * const newvalue, char * const replybuf, enum bfg_set_device_replytype * const out_success)
{
	struct ICARUS_INFO * const info = proc->device_data;
	if ((!strcasecmp(newvalue, "never")) || !strcasecmp(newvalue, "-r"))
		info->reopen_mode = IRM_NEVER;
	else
	if (!strcasecmp(newvalue, "timeout"))
		info->reopen_mode = IRM_TIMEOUT;
	else
	if ((!strcasecmp(newvalue, "cycle")) || !strcasecmp(newvalue, "r"))
		info->reopen_mode = IRM_CYCLE;
	else
	if (!strcasecmp(newvalue, "now"))
		info->reopen_now = true;
	else
		return "Invalid reopen mode";
	return NULL;
}

static void icarus_shutdown(struct thr_info *thr)
{
	//DUALMINER HACKING

	if(!opt_dualminer_test)
	{
		if(opt_scrypt)
		{
			open_ltc_unit(thr->cgpu->device_fd, LTC_UNIT_CLOSE);
		}
		else
		{
			open_btc_unit(thr->cgpu->device_fd, "0");
		}
		set_rts_status(thr->cgpu->device_fd, RTS_LOW);
		do_icarus_close(thr);
	}

	//END


	//do_icarus_close(thr);
	free(thr->cgpu_data);
}

const struct bfg_set_device_definition icarus_set_device_funcs[] = {
	// NOTE: Order of parameters below is important for --icarus-options
	{"baud"         , icarus_set_baud         , "serial baud rate"},
	{"work_division", icarus_set_work_division, "number of pieces work is split into"},
	{"fpga_count"   , icarus_set_fpga_count   , "number of chips working on pieces"},
	{"reopen"       , icarus_set_reopen       , "how often to reopen device: never, timeout, cycle, (or now for a one-shot reopen)"},
	// NOTE: Below here, order is irrelevant
	{"timing"       , icarus_set_timing       , "timing of device; see README.FPGA"},
	{NULL},
};

struct device_drv icarus_drv = {
	.dname = "dualminer",
	.name = "DM",
	.probe_priority = -115,
	.lowl_probe = icarus_lowl_probe,
	.get_api_stats = icarus_drv_stats,
	.thread_prepare = icarus_prepare,
	.thread_init = icarus_init,
	.scanhash = icarus_scanhash,
	.thread_disable = close_device_fd,
	.thread_shutdown = icarus_shutdown,
};
