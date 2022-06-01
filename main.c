#include "esmc.h"

static int stop;
static int debug;
static int show_packet;
static int option;
char ifName[IFNAMSIZ];

void sig_handler(int signum)
{
	stop = 1;
}

static int parse_config(char *filename)
{
#define SYNCE_CONF_LINE_SZ 128
	FILE *fp = NULL;
	char buf[SYNCE_CONF_LINE_SZ];
	char *key = NULL;
	char *val = NULL;

	if ((fp = fopen(filename, "r")) == NULL) {
		char err_msg[128];
		sprintf(err_msg, "Failed to open %s", ifName);
		SYNCE_ERR((const char *)err_msg);
		return -1;
	}

	/* Start parsing */
	while (!feof(fp)) {
		if (fgets(buf, SYNCE_CONF_LINE_SZ, fp) == NULL) {
			continue;
		}

		if ((buf[0] == '#') || (buf[0] == '\n' ||
             buf[0] == ' ') || ((key = strtok(buf, "=")) == NULL)) {
            continue;
        }

		/* Split the string by '=' delimeter */
        val = strtok(NULL, "=");
		if (val == NULL) {
			SYNCE_ERR("Invalid value");
			return -1;
		}

		/* Replace trailing newline char w/ end of line  */
        val[strcspn(val, "\n")] = '\0';

		if (strncmp(key, "interface", strlen("interface")) == 0) {
			if (strlen(ifName) > 0) {
				/* Already set from command-line args */
				continue;
			}
			strncpy(ifName, val, IFNAMSIZ - 1);
			ifName[IFNAMSIZ - 1] = '\0';
		} else if (strncmp(key, "debug", strlen("debug")) == 0) {
			if (debug) {
				/* Already set from command-line args */
				continue;
			}
			debug = (val[0] == 'y') ? 1 : 0;
		} else if (strncmp(key, "show_packet", strlen("show_packet")) == 0) {
			show_packet = (val[0] == 'y') ? 1 : 0;
		} else if (strncmp(key, "option", strlen("option")) == 0) {
			option = atoi(val);
		}
	}

	fclose(fp);

	return 0;
}

static int parse(int argc, char **argv)
{
	const char *opstr = "di:f:o:";
	int ch;

	memset(ifName, 0, sizeof(ifName));

	while ((ch = getopt(argc, argv, opstr)) != -1) {
		switch(ch) {
			case 'f':
				parse_config(optarg);
				break;
			case 'i':
				strncpy(ifName, optarg, IFNAMSIZ - 1);
				ifName[IFNAMSIZ - 1] = '\0';
				break;
			case 'd':
				debug = 1;
				break;
			case 'o':
				option = atoi(optarg);
				break;
			default:
				break;
		}
	}

	if (strlen(ifName) == 0) {
		strncpy(ifName, DEFAULT_IF, IFNAMSIZ - 1);
		ifName[IFNAMSIZ - 1] = '\0';
	}

	return 0;
}

static inline const char *ssm_code_op1_to_str(uint8_t ssm_code)
{
	/* Clear the 4 MSB */
	ssm_code &= 0x0F;

	switch (ssm_code) {
		case OP1_QL_PRC:
			return "PRC/PRTC/ePRTC";
		case OP1_QL_SSU_A:
			return "SSU_A";
		case OP1_QL_SSU_B:
			return "SSU_B";
		case OP1_QL_EEC1:
			return "EEC1/eEEC";
		case OP1_QL_DNU:
			return "DNU";
		default:
			return "";
	}

	return "";
}

static inline const char *ssm_code_op2_to_str(uint8_t ssm_code)
{
	/* Clear the 4 MSB */
	ssm_code &= 0x0F;

	switch (ssm_code) {
		case OP2_QL_STU:
			return "STU";
		case OP2_QL_PRS:
			return "PRS/PRTC/ePRTC";
		case OP2_QL_ST2:
			return "ST2";
		case OP2_QL_TNC:
			return "TNC";
		case OP2_QL_EEC2:
			return "EEC2/eEEC";
		case OP2_QL_ST3E:
			return "ST3E";
		case OP2_QL_PROV:
			return "PROV";
		case OP2_QL_DUS:
			return "DUS";
		default:
			return "";
	}

	return "";
}

int main(int argc, char **argv)
{
	int sockfd, i;
	int sockopt;
	ssize_t numbytes;
	struct ifreq ifopts;	/* set promiscuous mode */
	uint8_t buf[BUF_SIZ];

	/* Parse input args */
	parse(argc, argv);

	/* Header structures */
	struct ether_header *eh = (struct ether_header *) buf;

	/* Packet structure */
	struct esmc_msg *esmc = (struct esmc_msg *)buf;
	struct ql_tlv *ql_tlv = (struct ql_tlv *)&esmc->ql_tlv;

	/* Open PF_PACKET socket, listening for the Slow Protocol */
	if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_SLOW))) == -1) {
		SYNCE_ERR("listener: socket");	
		return -1;
	}

	/* Set interface to promiscuous mode - do we need to do this every time? */
	strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);
	ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
	ifopts.ifr_flags |= IFF_PROMISC;
	ioctl(sockfd, SIOCSIFFLAGS, &ifopts);
	/* Allow the socket to be reused - incase connection is closed prematurely */
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof sockopt) == -1) {
		SYNCE_ERR("setsockopt");
		close(sockfd);
		exit(EXIT_FAILURE);
	}
	/* Bind to device */
	if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ifName, IFNAMSIZ-1) == -1)	{
		char err_msg[128];
		sprintf(err_msg, "SO_BINDTODEVICE %s", ifName);
		SYNCE_ERR((const char *)err_msg);
		close(sockfd);
		exit(EXIT_FAILURE);
	}

	/* Register signal handler */
	signal(SIGINT, sig_handler);

	while (!stop) {
		numbytes = recvfrom(sockfd, buf, BUF_SIZ, 0, NULL, NULL);
			SYNCE_DBG("listener: got packet %lu bytes\n", numbytes);
			SYNCE_DBG("Destination MAC: %x:%x:%x:%x:%x:%x\n",
								eh->ether_dhost[0],
								eh->ether_dhost[1],
								eh->ether_dhost[2],
								eh->ether_dhost[3],
								eh->ether_dhost[4],
								eh->ether_dhost[5]);
		/* Check the packet is for me */
		if (eh->ether_dhost[0] == DEST_MAC0 &&
				eh->ether_dhost[1] == DEST_MAC1 &&
				eh->ether_dhost[2] == DEST_MAC2 &&
				eh->ether_dhost[3] == DEST_MAC3 &&
				eh->ether_dhost[4] == DEST_MAC4 &&
				eh->ether_dhost[5] == DEST_MAC5) {
			SYNCE_DBG("Correct destination MAC: %x:%x:%x:%x:%x:%x\n",
							eh->ether_dhost[0],
							eh->ether_dhost[1],
							eh->ether_dhost[2],
							eh->ether_dhost[3],
							eh->ether_dhost[4],
							eh->ether_dhost[5]);
		} else {
			continue;
		}

		if (show_packet || debug) {
			/* Print packet */
			SYNCE_INFO("\tData (%ldbytes):", numbytes);
			for (i=0; i<numbytes; i++) printf("%02x:", buf[i]);
			SYNCE_INFO("\n");
			SYNCE_INFO("ESMC - version: 0%X, event: 0x%X\n", esmc->version, esmc->event);
			SYNCE_INFO("QL TLV type: 0x%02X\n", ql_tlv->type);
			SYNCE_INFO("QL TLV length: 0x%02X 0x%02X\n", ql_tlv->len[0], ql_tlv->len[1]);
			SYNCE_INFO("SSM code: %s\n", (option == 1) ? ssm_code_op1_to_str(ql_tlv->ssm_code) :
														 ssm_code_op2_to_str(ql_tlv->ssm_code));
		}
	}

	/* Exit flow */
	close(sockfd);
	
	return 0;
}
