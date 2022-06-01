#ifndef ESMC_H
#define ESMC_H

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <signal.h>
#include <unistd.h> // for close

#define DEST_MAC0	0x01
#define DEST_MAC1	0x80
#define DEST_MAC2	0xC2
#define DEST_MAC3	0x00
#define DEST_MAC4	0x00
#define DEST_MAC5	0x02

#define ETHER_TYPE	0x0800

#define DEFAULT_IF	"eth0"
#define BUF_SIZ		1024

/* SSM code */
// option 1
#define OP1_QL_PRC      0b0010
#define OP1_QL_PRTC	   	0b0010
#define OP1_QL_ePRTC	0b0010
#define OP1_QL_SSU_A    0b0100
#define OP1_QL_SSU_B    0b1000
#define OP1_QL_EEC1	   	0b1011
#define OP1_QL_eEEC		0b1011
#define OP1_QL_DNU      0b1111

// option 2
#define OP2_QL_STU      0b0000
#define OP2_QL_PRS      0b0001
#define OP2_QL_PRTC     0b0001
#define OP2_QL_ePRTC    0b0001
#define OP2_QL_ST2      0b0111
#define OP2_QL_TNC      0b1000
#define OP2_QL_EEC2	    0b1010
#define OP2_QL_eEEC     0b1010
#define OP2_QL_ST3E     0b1101
#define OP2_QL_PROV     0b1110
#define OP2_QL_DUS      0b1111


#define SYNCE_INFO(fmt, ...) printf("[SyncE][Info] " fmt, ##__VA_ARGS__);
#define SYNCE_ERR(fmt) printf("[SyncE][ERROR] "); perror(fmt);
#define SYNCE_DBG(fmt, ...) if (debug) printf("[SyncE][DEBUG] " fmt, ##__VA_ARGS__);

struct ql_tlv {
	uint8_t type;
	uint8_t len[2];
	uint8_t ssm_code: 4,
			unused:   4;
};

struct esmc_msg {
	uint8_t dst_addr[6];
	uint8_t src_addr[6];
	uint8_t ethertype[2];
	uint8_t subtype;
	uint8_t itu_oui[3];
	uint8_t itu_subtype[2];
	uint8_t _reserved: 3,
			event:	   1,
			version:   4;
	uint8_t reserved[3];
    struct ql_tlv ql_tlv;
	uint8_t padding[35];
};

#endif // ESMC_H