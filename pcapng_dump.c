/*
    TLS parser utility.
    Takes a pcap file as input.
    Author - Debashis Chatterjee
*/


#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <getopt.h>
#include <errno.h>

#define PCAPNG_BLOCK_TYPE_RESERVED 0
#define PCAPNG_INTERFACE_DESCRIPTION_BLOCK 1
#define PCAPNG_PACKET_BLOCK 2
#define PCAPNG_SIMPLE_PACKET_BLOCK 3
#define PCAPNG_NAME_RESOLUTION_BLOCK 4
#define PCAPNG_INTERFACE_STATISTICS_BLOCK 5
#define PCAPNG_ENHANCED_PACKET_BLOCK 6
#define PCAPNG_IRIG_TIMESTAMP_BLOCK 7
#define PCAPNG_ARINC_429_IN_AFDX_BLOCK 8
#define PCAPNG_SECTION_HEADER_BLOCK 0x0a0d0d0a

typedef struct pcapng_general_block {
    uint32_t block_type;
    uint32_t block_total_length;
    unsigned char * p_block_body;
    uint32_t block_total_length_repeated;
}
    pcapng_general_block_t;

typedef struct pcap_hdr_s {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t  thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in octets */
    uint32_t network;        /* data link type */
}
    pcap_hdr_t;

typedef struct pcaprec_hdr_s {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
}
    pcaprec_hdr_t;

typedef struct ethernet_extended_s {
    unsigned char src_mac[6];
    unsigned char dst_mac[6];
    uint8_t ethtype[2];
    uint16_t tci_vlana;
    uint16_t ethertype_a;
    uint16_t tci_vlanb;
    uint16_t ethertype_b;
}
    ethernet_extended_t;

typedef struct ethernet_s {
    unsigned char src_mac[6];
    unsigned char dst_mac[6];
    uint8_t ethtype[2];
}
    ethernet_t;


typedef struct ipv4_s {
    unsigned char  version_and_ihl;
    unsigned char dscp_and_ecn;
    uint8_t total_length[2];
    uint8_t identification[2];
    uint8_t flags_and_fragment_offset[2];
    uint8_t  ttl;
    uint8_t  protocol;
    uint8_t csum[2];
    uint8_t src_ip[4];
    uint8_t dst_ip[4];
}
    ipv4_t;

typedef struct ipv6_s {
    uint8_t version_scsp_len_flowlabel[4];
    uint16_t  payload_len;
    uint8_t   next_header;
    uint8_t   hoplimit;
    unsigned char src_ip[16];
    unsigned char dst_ip[16];
}
    ipv6_t;

typedef struct arp_s {
    uint16_t hw_type;
    uint16_t prot_type;
    uint8_t hw_length;
    uint8_t prot_length;
    uint16_t opcode;
    unsigned char sender_hw_addr[6];
    uint32_t sender_prot_addr;
    unsigned char tgt_hw_addr[6];
    uint32_t tgt_prot_addr;
}
    arp_t;

typedef struct tcp_s {
    uint8_t src_port[2];
    uint8_t dst_port[2];
    uint8_t seq_number[4];
    uint8_t ack_number[4];
    uint8_t  offset_rsvd_flags[2];
    uint8_t window[2];
    uint8_t csum[2];
    uint8_t urgent[2];
}
    tcp_t;

typedef struct udp_s {
    uint8_t src_port[2];
    uint8_t dst_port[2];
    uint8_t udpsize[2];
    uint8_t csum[2];
}
    udp_t;

typedef struct vxlan_s {
    uint32_t flags_and_reserved;
    uint32_t vni_and_reserved2;
}
    vxlan_t;

typedef struct gtpu_s {
    uint8_t version_prot_type_reserved1_extern_hdr_seg_num_flag_ndpu_flag;
    uint8_t msg_type;
    uint16_t msg_len;
    uint32_t teid;
    uint16_t seq_num;
    uint8_t ndpu_num;
    uint8_t nxtext_hdr;
}
    gtpu_t;

typedef struct icmp_s {
    uint8_t type;
    uint8_t code;
    uint16_t hdr_chksum;
}
    icmp_t;

typedef struct protocol_version {
    uint8_t major;
    uint8_t minor;
}
    protocol_version_t;

int tls_port_number = 443;
int ip_total_length = 0;
int tls_record_length = 0;
int tls_record_length_ref = 0;

typedef enum content_type {
    change_cipher_spec = 20, 
    alert = 21, 
    handshake = 22,
    application_data = 23, 
    content_unknown = 255
}
    content_type_t;

typedef struct TLS_plaintext {
    uint8_t type;
    uint8_t version_high;
    uint8_t version_low;
    uint8_t length_high;
    uint8_t length_low;
}
    TLS_plaintext_t;

typedef struct TLS_handshake_message {
    uint8_t msg_type;
    uint8_t length_0;
    uint8_t length_1;
    uint8_t length_2;
}
   TLS_handshake_message_t;

typedef enum handshake_type {
    hello_request = 0,
    client_hello = 1,
    server_hello = 2,
    certificate = 11,
    server_key_exchange = 12,
    certificate_request = 13,
    server_hello_done = 14,
    certificate_verify = 15,
    client_key_exchange = 16,
    finished = 20,
    handshake_unknown = 255
}
    handshake_type_t;

typedef struct TLS_compressed {
    content_type_t type;
    protocol_version_t version;
    uint16_t length;
    unsigned char fragment[4];
}
    TLS_Compressed_t;

typedef struct {
    content_type_t type;
    protocol_version_t version;
    uint16_t length;
    unsigned char fragment[4];
    /* 
       select (SecurityParameters.cipher_type) {
           case stream: GenericStreamCipher;
           case block:  GenericBlockCipher;
           case aead:   GenericAEADCipher;
       } fragment;
    */
}
    TLS_Ciphertext_t;

typedef struct stream_ciphered {
    char content_TLSCompressed_length[4];;
    char MAC_SecurityParameters_mac_length[4];
}
    GenericStreamCipher_t;

/*
typedef struct {
     char IV_SecurityParameters_record_iv_length[4];
       block-ciphered struct {
           opaque content[TLSCompressed.length];
           opaque MAC[SecurityParameters.mac_length];
           uint8 padding[GenericBlockCipher.padding_length];
           uint8 padding_length;
       };
   } GenericBlockCipher;

   struct {
      opaque nonce_explicit[SecurityParameters.record_iv_length];
      aead-ciphered struct {
          opaque content[TLSCompressed.length];
      };
   } GenericAEADCipher;
*/
#define SSL_V30                 0x0300
#define TLS_V10                 0x0301
#define TLS_V11                 0x0302
#define TLS_V12                 0x0303
#define TLS_V13                 0x0304
#define DTLS_V10                0xFEFF
#define DTLS_V12                0xFEFD
#define DTLS_V13                0xFEFC

#define TLS_NEED_MORE_DATA       0
#define TLS_GENERIC_ERROR       -1
#define TLS_BROKEN_PACKET       -2
#define TLS_NOT_UNDERSTOOD      -3
#define TLS_NOT_SAFE            -4
#define TLS_NO_COMMON_CIPHER    -5
#define TLS_UNEXPECTED_MESSAGE  -6
#define TLS_CLOSE_CONNECTION    -7
#define TLS_COMPRESSION_NOT_SUPPORTED -8
#define TLS_NO_MEMORY           -9
#define TLS_NOT_VERIFIED        -10
#define TLS_INTEGRITY_FAILED    -11
#define TLS_ERROR_ALERT         -12
#define TLS_BROKEN_CONNECTION   -13
#define TLS_BAD_CERTIFICATE     -14
#define TLS_UNSUPPORTED_CERTIFICATE -15
#define TLS_NO_RENEGOTIATION    -16
#define TLS_FEATURE_NOT_SUPPORTED   -17
#define TLS_DECRYPTION_FAILED   -20

#define TLS_AES_128_GCM_SHA256                0x1301
#define TLS_AES_256_GCM_SHA384                0x1302
#define TLS_CHACHA20_POLY1305_SHA256          0x1303
#define TLS_AES_128_CCM_SHA256                0x1304
#define TLS_AES_128_CCM_8_SHA256              0x1305

#define TLS_RSA_WITH_AES_128_CBC_SHA          0x002F
#define TLS_RSA_WITH_AES_256_CBC_SHA          0x0035
#define TLS_RSA_WITH_AES_128_CBC_SHA256       0x003C
#define TLS_RSA_WITH_AES_256_CBC_SHA256       0x003D
#define TLS_RSA_WITH_AES_128_GCM_SHA256       0x009C
#define TLS_RSA_WITH_AES_256_GCM_SHA384       0x009D

// forward secrecy
#define TLS_DHE_RSA_WITH_AES_128_CBC_SHA      0x0033
#define TLS_DHE_RSA_WITH_AES_256_CBC_SHA      0x0039
#define TLS_DHE_RSA_WITH_AES_128_CBC_SHA256   0x0067
#define TLS_DHE_RSA_WITH_AES_256_CBC_SHA256   0x006B
#define TLS_DHE_RSA_WITH_AES_128_GCM_SHA256   0x009E
#define TLS_DHE_RSA_WITH_AES_256_GCM_SHA384   0x009F

#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA    0xC013
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA    0xC014
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 0xC027
#define TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 0xC02F
#define TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 0xC030

#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA    0xC009
#define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA    0xC00A
#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 0xC023
#define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 0xC024
#define TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 0xC02B
#define TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 0xC02C

#define TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256     0xCCA8
#define TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256   0xCCA9
#define TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256       0xCCAA

#define TLS_FALLBACK_SCSV                     0x5600
#define TLS_EMPTY_RENEGOTIATION_INFO_SCSV     0xFF

#define TLS_UNSUPPORTED_ALGORITHM   0x00
#define TLS_RSA_SIGN_RSA            0x01
#define TLS_RSA_SIGN_MD5            0x04
#define TLS_RSA_SIGN_SHA1           0x05
#define TLS_RSA_SIGN_SHA256         0x0B
#define TLS_RSA_SIGN_SHA384         0x0C
#define TLS_RSA_SIGN_SHA512         0x0D

#define TLS_EC_PUBLIC_KEY           0x11
#define TLS_EC_prime192v1           0x12
#define TLS_EC_prime192v2           0x13
#define TLS_EC_prime192v3           0x14
#define TLS_EC_prime239v1           0x15
#define TLS_EC_prime239v2           0x16
#define TLS_EC_prime239v3           0x17
#define TLS_EC_prime256v1           0x18
#define TLS_EC_secp224r1            21
#define TLS_EC_secp256r1            23
#define TLS_EC_secp384r1            24
#define TLS_EC_secp521r1            25

#define TLS_ALERT_WARNING           0x01
#define TLS_ALERT_CRITICAL          0x02

#define TLS_COMPRESSION_NULL        0x00
#define TLS_COMPRESSION_DEFLATE     0x01

int main(int argc, char *argv[]);
int dump_pcapng_block(unsigned char *, int, int );
int dump_pcapng_section_header_block(unsigned char *, int );
int dump_pcapng_enhanced_packet_block(unsigned char *, int );
void collect_tls_fields(unsigned char *);
void dump_tls_fields(unsigned char *, int );
void dump_tls_handshake_message(unsigned char *, int );
void dump_tls_handshake_hello_message(unsigned char * body, int, int );
void dump_tls_cipher_type(unsigned int );
void dump_tls_compression_type(unsigned int );

void dump_pcap_rec_header(pcaprec_hdr_t *, int );
void dump_pcap_data(unsigned char *, int, int );
void dump_pcap_ethernet_hdr(ethernet_t *);
void dump_pcap_ipv4_hdr(ipv4_t *);
void dump_pcap_ipv6_hdr(ipv6_t *);
void dump_pcap_udp_hdr(udp_t *);
void dump_pcap_tcp_hdr(tcp_t *);
void dump_hex_bytes(unsigned char*, int );
void dump_one_line(unsigned char*, int, int );

#define TLS_DEBUG 1

typedef enum eDebugLevel { 
    PCAPNG_INFO = 0,
    PCAP_INFO = 0,
    ETH_INFO = 1,
    IP_INFO = 2,
    IPV6_INFO = 2,
    TCP_INFO = 3,
    UDP_INFO = 3,
    TLS_INFO = 4,
    FATAL_INFO = 5
}
    DEBUG_LEVEL;

int current_debug_level = PCAPNG_INFO;
unsigned char * tls_data_ptr;
unsigned char * tls_data_ptr_ref;

/*
 * function prototype for debug printf
 */
void _debug_printf(DEBUG_LEVEL level, char *, ...);
__inline void _debug_printf(DEBUG_LEVEL level, char *format, ...)
{
#ifdef TLS_DEBUG
int i;

	va_list argp;
	if (level < current_debug_level) 
            return;
	//for (i = 0; i < level; i++)
        //    printf(" ");
        va_start(argp, format);
	vprintf(format, argp);
	va_end(argp);
	//fflush(NULL);
#endif
}


int main(int argc, char *argv[])
{
FILE * fh;
int res;
pcapng_general_block_t pgbt;
pcaprec_hdr_t prht;
int block_index = 1;
unsigned char jumbo_frame[16384];
int pkt_len = 0;
char * pcapng_file_name = NULL;
unsigned int i;
unsigned char * p_pcap_general_block_data;
unsigned int block_type;
unsigned int block_byte_count;
unsigned int block_byte_count_repeated;
int option_index = 0;
int c;

struct option long_options[] = {
    { "file-name",        required_argument,  NULL, 'f' },
    { "tls-port",        required_argument,  NULL, 't' },
    { "debug-level",     required_argument,  NULL, 'd' },
    { 0, 0, 0, 0}
};

char *optstring = "f:t:d:";
    if (argc == 1) {
        _debug_printf(FATAL_INFO, "Usage - pcapng_dump --file-name pcapng_file_name [optional --tls-port tls_port_number] [optional --debug-level debug_level]\n");
        return(1);
    } 
    while (1) {
        c = getopt_long(argc, argv, optstring, long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 'f': 
                pcapng_file_name = optarg;
                break;
            case 't': 
                tls_port_number  = atoi(optarg);
                break;
            case 'd':
                current_debug_level = atoi(optarg);
                break;
            default:
                _debug_printf(FATAL_INFO, "Usage - pcapng_dump --file-name pcapng_file_name [optional --tls-port tls_port_number] [optional --debug-level debug_level]\n");
                return(1);
        }
    }
    printf("Capture file = %s, TLS port = %d, debug level = %d\n", pcapng_file_name, tls_port_number, current_debug_level );
    fh = fopen(pcapng_file_name, "rb");
    if (fh == NULL) {
        _debug_printf(FATAL_INFO, "Error - file %s not found\n", pcapng_file_name);
        return 1;
    }
    while (!feof(fh)) {
        _debug_printf(PCAPNG_INFO,"Reading pcapng block header %d\n", block_index);
        res = fread((char *)&block_type, 1, sizeof(int), fh);
        if (res != sizeof(int)) {
            _debug_printf(FATAL_INFO, "Error - can not read pcapng block header type from file %s\n", pcapng_file_name);
            fclose(fh);
            return 1;
        }
        res = fread((char *)&block_byte_count, 1, sizeof(int), fh);
        if (res != sizeof(int)) {
            _debug_printf(FATAL_INFO, "Error - can not read pcapng block byte count from file %s\n", pcapng_file_name);
            fclose(fh);
            return 1;
        }
        i = block_byte_count - 12;
        if (i != 0) {
            p_pcap_general_block_data = (unsigned char *)malloc(i);
            res = fread(p_pcap_general_block_data, 1, i, fh);
            if (res != i) {
                 _debug_printf(FATAL_INFO, "Error - can not read %d pcapng block bytes from file %s, only read %d bytes\n", i, pcapng_file_name, res);
                 fclose(fh);
                 return 1;
            }
        }
        res = fread((char *)&block_byte_count_repeated, 1, sizeof(int), fh);
        if (res != sizeof(int)) {
            _debug_printf(FATAL_INFO, "Error - can not read pcapng block byte count repeated from file %s\n", pcapng_file_name);
            fclose(fh);
            return 1;
        }
        if (block_byte_count_repeated != block_byte_count) {
            _debug_printf(FATAL_INFO, "Error, block byte count %d does not match repeated block byte count %d\n", block_byte_count, block_byte_count_repeated);
            return 1;
        }
        dump_pcapng_block(p_pcap_general_block_data, block_type, block_byte_count);
        free(p_pcap_general_block_data);
        block_index++;
     }
     return 0;
}

int dump_pcapng_block(unsigned char * p_block, int block_type, int byte_count )
{
    _debug_printf(PCAPNG_INFO, "PCAPNG block type ID = %x\n", block_type);
    if (block_type == PCAPNG_SECTION_HEADER_BLOCK) { 
         _debug_printf(PCAPNG_INFO, "Block type = section header\n");
         return dump_pcapng_section_header_block(p_block, byte_count );
    }
    else if (block_type == PCAPNG_INTERFACE_DESCRIPTION_BLOCK) { 
         _debug_printf(PCAPNG_INFO, "Block type = interface description\n");
         return dump_pcapng_section_header_block(p_block, byte_count );
    }
    else  if (block_type == PCAPNG_ENHANCED_PACKET_BLOCK) { 
         _debug_printf(PCAPNG_INFO, "Block type = enhanced packet\n");
         return dump_pcapng_enhanced_packet_block(p_block, byte_count );
    }
    else if (block_type == PCAPNG_SIMPLE_PACKET_BLOCK) { 
         _debug_printf(PCAPNG_INFO, "Block type = simple packet\n");
         return dump_pcapng_section_header_block(p_block, byte_count );
    }
    else if (block_type == PCAPNG_PACKET_BLOCK) { 
         _debug_printf(PCAPNG_INFO, "Block type = packet\n");
         return dump_pcapng_section_header_block(p_block, byte_count );
    }
    else if (block_type == PCAPNG_NAME_RESOLUTION_BLOCK) { 
         _debug_printf(PCAPNG_INFO, "Block type = name resolution\n");
         return dump_pcapng_section_header_block(p_block, byte_count );
    }
    else if (block_type == PCAPNG_INTERFACE_STATISTICS_BLOCK) { 
         _debug_printf(PCAPNG_INFO, "Block type = interface statistics\n");
         return dump_pcapng_section_header_block(p_block, byte_count );
    }
    else if (block_type == PCAPNG_SECTION_HEADER_BLOCK) { 
         _debug_printf(PCAPNG_INFO, "Block type = section header\n");
         return dump_pcapng_section_header_block(p_block, byte_count );
    }
    return 0;
     
} 

int dump_pcapng_section_header_block(unsigned char * p_block, int byte_count )
{ 
   return 0;
}

int packet_index = 1;
int dump_pcapng_enhanced_packet_block(unsigned char * p_block, int byte_count )
{ 
struct tm my_tm;
struct tm *p_tm;
time_t tx;
int block_length;
int block_length_repeated;
int captured_length;
int packet_length;


    _debug_printf(PCAPNG_INFO, "\n **** Header info for packet %d ****\n", packet_index);
    block_length = *(int *)p_block;
    _debug_printf(PCAPNG_INFO,"Block length = %d\n", block_length);
    p_block+=sizeof(int);
    tx = (time_t)p_block;
    p_tm = localtime_r(&tx, &my_tm);
    _debug_printf(PCAPNG_INFO, "Time stamp = %02d-%02d-%04d %02d:%02d:%02d sec\n", p_tm->tm_mon+1, p_tm->tm_mday, p_tm->tm_year+1900,
        p_tm->tm_hour, p_tm->tm_min, p_tm->tm_sec );
    p_block+=2*sizeof(int);
    captured_length = *(int *)p_block;
    p_block+=sizeof(int);
    packet_length = *(int *)p_block;
    p_block+=sizeof(int);
    _debug_printf(PCAPNG_INFO, "Captured length = %d\n", captured_length);
    _debug_printf(PCAPNG_INFO, "Actual length of packet = %d\n", packet_length);
    dump_pcap_data(p_block, packet_index++, captured_length);
    p_block+=(captured_length/4)*4;
    block_length_repeated=*(int *)p_block;
    _debug_printf(PCAPNG_INFO, "Repeated block length = %d\n", block_length_repeated);
    return 0;
}
 
void dump_pcap_header(pcap_hdr_t * lph)
{
    _debug_printf(PCAP_INFO,"PCAP magic number = %X\n", lph->magic_number);
    _debug_printf(PCAP_INFO,"PCAP version number = %d.%d\n", lph->version_major, lph->version_minor);
    _debug_printf(PCAP_INFO,"PCAP thiszone(GMT to local correction) = %d\n", lph->thiszone);
    _debug_printf(PCAP_INFO,"PCAP sigfigs(accuracy of time stamps) = %d\n", lph->sigfigs);
    _debug_printf(PCAP_INFO,"PCAP snaplen(max length of captured packets) = %d\n", lph->snaplen);
    _debug_printf(PCAP_INFO,"PCAP network(data link type) = %d\n", lph->network);
}
void dump_pcap_rec_header(pcaprec_hdr_t * lprh, int pkt_index )
{     
struct tm my_tm;
struct tm *p_tm;
time_t tx;

    _debug_printf(PCAP_INFO,"\n **** Header info for packet %d ****\n", pkt_index);
    tx = (time_t)lprh->ts_sec;
    p_tm = localtime_r(&tx, &my_tm);
    _debug_printf(PCAP_INFO,"Time stamp = %02d-%02d-%04d %02d:%02d:%02d.%d sec\n", p_tm->tm_mon+1, p_tm->tm_mday, p_tm->tm_year+1900,
        p_tm->tm_hour, p_tm->tm_min, p_tm->tm_sec, lprh->ts_usec);
    _debug_printf(PCAP_INFO,"Number of octets of packet seved in file = %d\n", lprh->incl_len);
    _debug_printf(PCAP_INFO,"Actual length of packet = %d\n", lprh->orig_len);
}


void dump_pcap_data(unsigned char * pkt_buffer, int pkt_index, int pkt_len)
{
ethernet_t * peth;
int ethtype;
int ipversion = 4;
int prtcol = 6;
ipv4_t * pipv4;
ipv6_t * pipv6;
tcp_t * ptcp;
udp_t * pudp;

    peth = (ethernet_t *)pkt_buffer;
    ethtype = (peth->ethtype[0] << 8) | peth->ethtype[1];
    if (ethtype == 0x800) {
        dump_pcap_ethernet_hdr(peth);
        pkt_buffer+=sizeof(ethernet_t);
        ipversion = (((*pkt_buffer) & 0xF0)>>4);
        if (ipversion == 4) {
            pipv4 = (ipv4_t *)pkt_buffer;
            dump_pcap_ipv4_hdr(pipv4);
            pkt_buffer+=sizeof(ipv4_t);
            prtcol = pipv4->protocol;
                    
        }
        else if (ipversion == 6) {
            pipv6 = (ipv6_t *)pkt_buffer;
            dump_pcap_ipv6_hdr(pipv6);
            pkt_buffer+=sizeof(ipv6_t);
            prtcol = 0;
        }
        switch(prtcol) {
            case 6:
                ptcp = (tcp_t *)pkt_buffer;
                dump_pcap_tcp_hdr(ptcp);
                break;
            case 17:
                pudp = (udp_t *)pkt_buffer;
                dump_pcap_udp_hdr(pudp);
         }
    }
}

void dump_pcap_ethernet_hdr(ethernet_t * peth )
{
    _debug_printf(ETH_INFO, "Ethernet hdr\n");
    _debug_printf(ETH_INFO, "Src MAC = %X:%X:%X:%X:%X:%X\n", peth->src_mac[0], 
       peth->src_mac[1], peth->src_mac[2], peth->src_mac[3],
       peth->src_mac[4], peth->src_mac[5]);
    _debug_printf(ETH_INFO, "Dest MAC = %X:%X:%X:%X:%X:%X\n", peth->dst_mac[0], 
       peth->dst_mac[1], peth->dst_mac[2], peth->dst_mac[3],
       peth->dst_mac[4], peth->dst_mac[5]);
    _debug_printf(ETH_INFO, "Ether type = %02X%02X\n", peth->ethtype[0], peth->ethtype[1]);
}


void dump_pcap_ipv4_hdr(ipv4_t * pipv4)
{
int version;
int ihl;
int dscp;
int ecn;
int totlen;
int ident;
int flags;
int fragoff;
int cksum;


    _debug_printf(IP_INFO, "IPv4 header\n");
    version = (pipv4->version_and_ihl)>>4;
    ihl = (pipv4->version_and_ihl )&0x0F;
    _debug_printf(IP_INFO, "IP version = %d\n", version);
    _debug_printf(IP_INFO, "IP header length = %d\n", ihl*4);
    dscp = (pipv4->dscp_and_ecn) >> 2;
    ecn = (pipv4->dscp_and_ecn) & 0x3;
    _debug_printf(IP_INFO, "DSCP = %d\n", dscp);
    _debug_printf(IP_INFO, "ECN = %d\n", ecn);
    totlen = (pipv4->total_length[0] << 8) | pipv4->total_length[1];
    _debug_printf(IP_INFO, "Total length = %d\n", totlen);
    ip_total_length = totlen;
    ident = (pipv4->identification[0] << 8) | pipv4->identification[1];
    _debug_printf(IP_INFO, "Identification field = %X\n", ident);
    flags = pipv4->flags_and_fragment_offset[0] >> 5;
    fragoff = ((pipv4->flags_and_fragment_offset[0]&0x1F)>>8) | pipv4->flags_and_fragment_offset[1];
    _debug_printf(IP_INFO, "Flags = %d\n", flags);
    _debug_printf(IP_INFO, "Fragmentation offset = %d\n", fragoff);
    _debug_printf(IP_INFO,"TTL = %d\n", pipv4->ttl);
    _debug_printf(IP_INFO, "Protocol = %d\n", pipv4->protocol);
    cksum = (pipv4->csum[0] << 8) | pipv4->csum[1];
    _debug_printf(IP_INFO, "Checksum = %X\n", cksum);
    _debug_printf(IP_INFO, "Source IP address = %d.%d.%d.%d\n", pipv4->src_ip[0], pipv4->src_ip[1], pipv4->src_ip[2], pipv4->src_ip[3]);
    _debug_printf(IP_INFO, "Destination IP address = %d.%d.%d.%d\n", pipv4->dst_ip[0], pipv4->dst_ip[1], pipv4->dst_ip[2], pipv4->dst_ip[3]);
    ip_total_length -= sizeof(ipv4_t);
}          

void dump_pcap_ipv6_hdr(ipv6_t * pipv6)
{
    _debug_printf(IPV6_INFO,"IPv6 header\n");

}

void dump_pcap_udp_hdr(udp_t * pudp)
{
uint16_t srcpt;
uint16_t dstpt;
uint16_t udpsz;
uint16_t udpcsum;

    _debug_printf(UDP_INFO, "UDP header\n");
    srcpt = (pudp->src_port[0] << 8) | pudp->src_port[1];
    dstpt = (pudp->dst_port[0] << 8) | pudp->dst_port[1];
    udpsz = (pudp->udpsize[0] << 8) | pudp->udpsize[1];
    udpcsum = (pudp->csum[0] << 8) | pudp->csum[1];
    _debug_printf(UDP_INFO, "UDP source port = %d\n", srcpt);
    _debug_printf(UDP_INFO, "UDP destination port = %d\n", dstpt);
    _debug_printf(UDP_INFO, "UDP packet size = %d\n", udpsz);
    _debug_printf(UDP_INFO, "UDP checksum = %d\n", udpcsum);
}

void dump_pcap_tcp_hdr(tcp_t * ptcp)
{
uint16_t srcpt;
uint16_t dstpt;
uint32_t seq_number;
uint32_t ack_number;
uint16_t tcp_window;
uint16_t tcp_cksum;
uint16_t urgent_ptr;
int tcp_offset;
int tcp_flags;
int tcp_ns;
int tcp_cwr;
int tcp_ece;
int tcp_urg;
int tcp_ack;
int tcp_psh;
int tcp_rst;
int tcp_syn;
int tcp_fin;
unsigned char * p_tls_ssl_data;

    _debug_printf(TCP_INFO, "TCP header\n");
    srcpt = (ptcp->src_port[0] << 8) | ptcp->src_port[1];
    dstpt = (ptcp->dst_port[0] << 8) | ptcp->dst_port[1];
    seq_number = (ptcp->seq_number[0] << 24) | (ptcp->seq_number[1] << 16) | (ptcp->seq_number[2] << 8) | ptcp->seq_number[3];
    ack_number = (ptcp->ack_number[0] << 24) | (ptcp->ack_number[1] << 16) | (ptcp->ack_number[2] << 8) | ptcp->ack_number[3];
    tcp_window = (ptcp->window[0] << 8) | ptcp->window[1];
    tcp_cksum = (ptcp->csum[0] << 8) | ptcp->csum[1];
    urgent_ptr = (ptcp->urgent[0] << 8) | ptcp->urgent[1];
    tcp_offset = (ptcp->offset_rsvd_flags[0] & 0xF0) >> 4;
    tcp_ns = ptcp->offset_rsvd_flags[0] & 1;
    tcp_cwr = (ptcp->offset_rsvd_flags[1] & 0x80) >> 7;
    tcp_ece = (ptcp->offset_rsvd_flags[1] & 0x40) >> 6;
    tcp_urg = (ptcp->offset_rsvd_flags[1] & 0x20) >> 5;
    tcp_ack = (ptcp->offset_rsvd_flags[1] & 0x10) >> 4;
    tcp_psh = (ptcp->offset_rsvd_flags[1] & 0x08) >> 3;
    tcp_rst = (ptcp->offset_rsvd_flags[1] & 0x04) >> 2;
    tcp_syn = (ptcp->offset_rsvd_flags[1] & 0x02) >> 1;
    tcp_fin = (ptcp->offset_rsvd_flags[1] & 0x01);
    _debug_printf(TCP_INFO, "TCP source port = %d\n", srcpt);
    _debug_printf(TCP_INFO, "TCP destination port = %d\n", dstpt);
    _debug_printf(TCP_INFO, "TCP sequence number = %u\n", seq_number);
    _debug_printf(TCP_INFO, "TCP acknowledgement number = %u\n", ack_number);
    _debug_printf(TCP_INFO, "TCP window = %d\n", tcp_window);
    _debug_printf(TCP_INFO, "TCP checksum = %d\n", tcp_cksum);
    _debug_printf(TCP_INFO, "TCP urgent ptr = %d\n", urgent_ptr);
    _debug_printf(TCP_INFO, "TCP flags -> ");
    if (tcp_ns == 1) 
        _debug_printf(TCP_INFO,"NS ");
    if (tcp_cwr == 1) 
        _debug_printf(TCP_INFO,"CWR ");
    if (tcp_urg == 1) 
        _debug_printf(TCP_INFO,"URG ");
    if (tcp_ack == 1) 
        _debug_printf(TCP_INFO,"ACK ");
    if (tcp_psh == 1) 
        _debug_printf(TCP_INFO,"PSH ");
    if (tcp_rst == 1) 
        _debug_printf(TCP_INFO,"RST ");
    if (tcp_syn == 1) 
        _debug_printf(TCP_INFO,"SYN ");
    if (tcp_fin == 1) 
        _debug_printf(TCP_INFO,"FIN ");
    _debug_printf(TCP_INFO,"\n");
 
    if ((dstpt == tls_port_number) || (srcpt == tls_port_number)) {
        p_tls_ssl_data = (unsigned char *)ptcp;
        p_tls_ssl_data += sizeof(tcp_t);
        ip_total_length -= sizeof(tcp_t);
        if (tcp_offset > 5) {
            p_tls_ssl_data += (tcp_offset - 5) * sizeof(int);
            ip_total_length -= (tcp_offset - 5) * sizeof(int);
        }
        _debug_printf(TCP_INFO,"TCP payload size = %d\n", ip_total_length);
        if (ip_total_length > 0)
            collect_tls_fields(p_tls_ssl_data);
   }
    
}


void collect_tls_fields(unsigned char *body )
{
TLS_plaintext_t * ptls_t;
unsigned char * data_dump = body;
int ip_total_dump_length = ip_total_length;
int n_bytes;

   do {
        //_debug_printf(TLS_INFO,"Beginning of the do loop, ip_total_length = %d, tls_record_length = %d\n", ip_total_length, tls_record_length );
        ptls_t = (TLS_plaintext_t *)body;
 
        if (tls_record_length > 0) {
            _debug_printf(TLS_INFO, "Continuation of previous TLS packet\n");
            if (ip_total_length >= tls_record_length) {
                n_bytes = tls_record_length;
                ip_total_length -= tls_record_length;
                memcpy(tls_data_ptr, body, n_bytes);
                body+=n_bytes;
                tls_data_ptr+=n_bytes;
                dump_tls_fields(tls_data_ptr_ref, tls_record_length);
                free(tls_data_ptr_ref);
                tls_record_length = 0;
            }
            else {
                n_bytes = ip_total_length;
                tls_record_length -= ip_total_length;
                memcpy(tls_data_ptr, body, n_bytes );
                body+=n_bytes;
                tls_data_ptr+=n_bytes;
                ip_total_length = 0;
            }
            goto part_of_tls_packet;
        }
        if ((ptls_t->version_high == 3) && (ptls_t->version_low == 0)) 
            _debug_printf(TLS_INFO,"Packet %d is an SSL 3.0 packet\n", packet_index);
        else if ((ptls_t->version_high == 3) && (ptls_t->version_low == 1)) 
            _debug_printf(TLS_INFO,"Packet %d is a TSL 1.0 packet\n", packet_index);

        else if ((ptls_t->version_high == 3) && (ptls_t->version_low == 2)) 
            _debug_printf(TLS_INFO,"Packet %d is a TLS 1.1 packet\n", packet_index);
    
        else if ((ptls_t->version_high == 3) && (ptls_t->version_low == 3)) 
            _debug_printf(TLS_INFO,"Packet %d is a TLS 1.2 packet\n", packet_index);
    
        else if ((ptls_t->version_high == 3) && (ptls_t->version_low == 4)) 
            _debug_printf(TLS_INFO,"Packet %d is a TLS 1.3 packet\n", packet_index);
        else {
           _debug_printf(TLS_INFO,"Packet %d does not have version information, possibly SSL 2.0 packet\n");
           _debug_printf(TLS_INFO,"Error dump is as follows\n");
           //dump_hex_bytes(data_dump, ip_total_dump_length);
           ip_total_length = 0;
           tls_record_length = 0;
           goto part_of_tls_packet;
        }
        ip_total_length -= sizeof(TLS_plaintext_t);
        tls_record_length_ref = ((ptls_t->length_high) << 8) + ptls_t->length_low;
        tls_record_length = tls_record_length_ref;
        _debug_printf(TLS_INFO,"TLS record length = %d\n", tls_record_length);
        tls_data_ptr_ref = (unsigned char *)malloc(tls_record_length+sizeof(TLS_plaintext_t));
        if (tls_data_ptr_ref == NULL) {
            _debug_printf(FATAL_INFO, "Error, ran out of memory while allocating %d bytes for TLS record\n", (tls_record_length+sizeof(TLS_plaintext_t)) );
            exit(1);
        }
        tls_data_ptr = tls_data_ptr_ref;
        memset(tls_data_ptr, 0, tls_record_length );

       if (tls_record_length <= ip_total_length) {
            //dump_hex_bytes(body, tls_record_length);
            ip_total_length -= tls_record_length;
            memcpy(tls_data_ptr, body, tls_record_length+sizeof(TLS_plaintext_t));
            body+= tls_record_length+sizeof(TLS_plaintext_t);
            dump_tls_fields(tls_data_ptr_ref, tls_record_length );
            free(tls_data_ptr_ref);
            tls_record_length = 0;
        }
        else {
            //dump_hex_bytes(body, ip_total_length);
            memcpy(tls_data_ptr, body, ip_total_length );
            tls_data_ptr+=ip_total_length;
            tls_record_length -= ip_total_length;
            ip_total_length = 0;
        }
part_of_tls_packet:
        ;
        //_debug_printf(TLS_INFO,"End of the do loop, ip_total_length = %d, tls_record_length = %d\n", ip_total_length, tls_record_length );

    }
        while (ip_total_length > 0);

}

void dump_tls_fields(unsigned char * body, int tls_length )
{
TLS_plaintext_t * ptls_t;

    ptls_t = (TLS_plaintext_t *)body;
    if (ptls_t->type == change_cipher_spec) 
        _debug_printf(TLS_INFO,"TLS packet type = Change Cipher Spec\n");
    else if (ptls_t->type == alert) 
        _debug_printf(TLS_INFO,"TLS packet type = Alert\n");
    else if (ptls_t->type == handshake) { 
        _debug_printf(TLS_INFO,"TLS packet type = Handshake\n");
        dump_tls_handshake_message(body+sizeof(TLS_plaintext_t), tls_length );
    }
    else if (ptls_t->type == application_data) 
        _debug_printf(TLS_INFO,"TLS packet type = Application Data\n");
    else
        _debug_printf(TLS_INFO,"TLS packet type = %d Encrypted\n", ptls_t->type);

    dump_hex_bytes(tls_data_ptr_ref, tls_record_length_ref+sizeof(TLS_plaintext_t) );
}

void dump_tls_handshake_message(unsigned char * body, int data_length )
{
TLS_handshake_message_t * pthm;
int handshake_length;

    pthm = (TLS_handshake_message_t *)body;
    handshake_length = ((pthm->length_0)<<16) + ((pthm->length_1)<<8) + (pthm->length_2);
    _debug_printf(TLS_INFO, "TLS handshake message_length = %d\n", handshake_length );
    _debug_printf(TLS_INFO,"TLS Handshake message type = ");
    switch(pthm->msg_type) {
        case hello_request:
            _debug_printf(TLS_INFO,"Hello request\n");
            break;
        case client_hello:
            _debug_printf(TLS_INFO,"Client hello\n");
            dump_tls_handshake_hello_message(body+sizeof(TLS_handshake_message_t), handshake_length, client_hello );
            break;
        case server_hello:
            _debug_printf(TLS_INFO,"Server hello\n");
            dump_tls_handshake_hello_message(body+sizeof(TLS_handshake_message_t), handshake_length, server_hello );
            break;
        case certificate:
            _debug_printf(TLS_INFO,"Certificate\n");
            break;
        case server_key_exchange:
            _debug_printf(TLS_INFO,"Server key exchange\n");
            break;
        case certificate_request:
            _debug_printf(TLS_INFO,"Certificate request\n");
            break;
        case server_hello_done:
            _debug_printf(TLS_INFO,"Server hello done\n");
            break;
        case client_key_exchange:
            _debug_printf(TLS_INFO,"Client key exchange\n");
            break;
        case certificate_verify:
            _debug_printf(TLS_INFO,"Certificate verify\n");
            break;
        case finished:
            _debug_printf(TLS_INFO,"Finished\n");
            break;
        default:
            _debug_printf(TLS_INFO,"Encrypted handshake message type %d\n", pthm->msg_type);
            break;
    }

}

void dump_tls_handshake_hello_message(unsigned char * body, int tls_length, int hello_id )
{
int i;
int x;
int session_id_length;
int cipher_suites_length;
int compression_suites_length;
unsigned char version_high;
unsigned char version_low;
struct tm tmx;
struct tm *p_tm1 = &tmx;
unsigned char tmbuf[4];
unsigned long tm1;
time_t tm11;
char buf[80];


    version_high = *body++;
    version_low = *body++;
    if ((version_high == 3) && (version_low == 0)) 
            _debug_printf(TLS_INFO,"Client hello version is SSL 3.0\n");
        else if ((version_high == 3) && (version_low == 1)) 
            _debug_printf(TLS_INFO,"Client hello version is TSL 1.0\n");

        else if ((version_high == 3) && (version_low == 2)) 
            _debug_printf(TLS_INFO,"Client hello version is TLS 1.1\n");
    
        else if ((version_high == 3) && (version_low == 3)) 
            _debug_printf(TLS_INFO,"Client hello version is TLS 1.2\n");
    
        else if ((version_high == 3) && (version_low == 4)) 
            _debug_printf(TLS_INFO,"Client hello version is TLS 1.3\n");
        else 
           _debug_printf(TLS_INFO,"Client hello does not have version information, possibly SSL 2.0\n");
     
    for (i = 0; i < 4; i++)
        tmbuf[3-i] = body[i];
    body+=4;
    tm1 = *(long *)tmbuf;
    tm11 = (time_t)tm1;
    p_tm1 = localtime_r((time_t *)&tm11, &tmx);
    if (p_tm1 != NULL) {
         _debug_printf(TLS_INFO, "GMT unix time = ");
         _debug_printf(TLS_INFO, "%02d-%02d-%02d %02d:%02d:%02d\n", 
         p_tm1->tm_mon, p_tm1->tm_mday, p_tm1->tm_year, p_tm1->tm_hour, p_tm1->tm_min, p_tm1->tm_sec );
    }
    else 
         _debug_printf(TLS_INFO, "GMT unix time = %X\n", tm1);
    _debug_printf(TLS_INFO, "Random bytes = 0x");
    for (i = 0; i < 28; i++)
        _debug_printf(TLS_INFO, "%02X", body[i]);
    _debug_printf(TLS_INFO, "\n");
    body+=28;
    if (*body == 0)
        body++;
    else {
        session_id_length = *body++;
        _debug_printf(TLS_INFO, "Session ID = 0x");
        for (i = 0; i < session_id_length; i++) 
            _debug_printf(TLS_INFO, "%02X", *(body+i));
        _debug_printf(TLS_INFO, "\n");
        body+=session_id_length;
    }
    if (hello_id == client_hello) {
        x=((*body)<<8) + (*(body+1));
        body+=2;
        if (x!=0) {
            cipher_suites_length = x >> 1;
            _debug_printf(TLS_INFO, "# of cipher suites = %d\n", cipher_suites_length);
            for (i = 0; i < cipher_suites_length; i++) {
                x=((*body)<<8) + (*(body+1));
                _debug_printf(TLS_INFO, "Cipher suite[%d] = %X (", i, x);
                dump_tls_cipher_type(x);
                _debug_printf(TLS_INFO, ")\n");
                body+=2;
            }
        }          
        if (*body == 0)
            body++;
        else {
            compression_suites_length = *body++;
            _debug_printf(TLS_INFO, "# of compression suites = %d\n", compression_suites_length);
            for (i = 0; i < compression_suites_length; i++) {
                x=*body++;
                _debug_printf(TLS_INFO, "Compression suite[%d] = %X (", i, x);
                dump_tls_compression_type(x);
                _debug_printf(TLS_INFO, ")\n");
            }
        }
    }
    else if (hello_id == server_hello) {
        x=((*body)<<8) + (*(body+1));
        body+=2;
        _debug_printf(TLS_INFO, "Cipher suite = %X (", x);
        dump_tls_cipher_type(x);
        _debug_printf(TLS_INFO, ")\n");
        x=*body++;
        _debug_printf(TLS_INFO, "Compression suite = %X (", x);
        dump_tls_compression_type(x);
        _debug_printf(TLS_INFO, ")\n");
    }
}



typedef struct cipher_string {
    char cipher_name[50];
    int cipher_name_id;
}
    cipher_string_t;

cipher_string_t tls_ciphers[] = { 
        {
		"TLS_AES_128_GCM_SHA256",
		TLS_AES_128_GCM_SHA256
	},
	{
		"TLS_AES_256_GCM_SHA384",
		TLS_AES_256_GCM_SHA384
	},
	{
		"TLS_CHACHA20_POLY1305_SHA256",
		TLS_CHACHA20_POLY1305_SHA256
	},
	{
		"TLS_AES_128_CCM_SHA256",
		TLS_AES_128_CCM_SHA256
	},
	{
		"TLS_AES_128_CCM_8_SHA256",
		TLS_AES_128_CCM_8_SHA256
	},
	{
		"TLS_RSA_WITH_AES_128_CBC_SHA",
		TLS_RSA_WITH_AES_128_CBC_SHA
	},
	{
		"TLS_RSA_WITH_AES_256_CBC_SHA",
		TLS_RSA_WITH_AES_256_CBC_SHA
	},
	{
		"TLS_RSA_WITH_AES_128_CBC_SHA256",
		TLS_RSA_WITH_AES_128_CBC_SHA256
	},
	{
		"TLS_RSA_WITH_AES_256_CBC_SHA256",
		TLS_RSA_WITH_AES_256_CBC_SHA256
	},
	{
		"TLS_RSA_WITH_AES_128_GCM_SHA256",
		TLS_RSA_WITH_AES_128_GCM_SHA256
	},
	{
		"TLS_RSA_WITH_AES_256_GCM_SHA384",
		TLS_RSA_WITH_AES_256_GCM_SHA384
	},
        {
		"TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
		TLS_DHE_RSA_WITH_AES_128_CBC_SHA
	},
	{
		"TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
		TLS_DHE_RSA_WITH_AES_256_CBC_SHA
	},
	{
		"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
		TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
	},
	{
		"TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
		TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
	},
	{
		"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
		TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
	},
	{
		"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
		TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
	},
	{
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
	},
	{
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
	},
	{
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
	},
	{
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	},
	{
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	},
	{
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
	},
	{
		"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
                TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
        },
        {
                "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
                TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
        },
        {
                "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
                TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
        },
        {
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        },
        {
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        },
        {
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        },
        {
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        },
        {
                "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        },
        {
                "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
                TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        }
};

void dump_tls_cipher_type (unsigned int cipher_id )
{
int i;

    for (i = 0; i < (sizeof(tls_ciphers)/sizeof(cipher_string_t)); i++) {
        if (tls_ciphers[i].cipher_name_id == cipher_id) {
            _debug_printf(TLS_INFO, " %s ", tls_ciphers[i].cipher_name );
            return;
        }
    }
    _debug_printf(TLS_INFO, " UNKNOWN ");
}

typedef struct compression_string {
    char compression_name[50];
    int compression_name_id;
}
    compression_string_t;

compression_string_t tls_compressions[] = {
        {       
                "TLS_COMPRESSION_NULL",
                TLS_COMPRESSION_NULL
        },
        {
                "TLS_COMPRESSION_DEFLATE",
                TLS_COMPRESSION_DEFLATE
        }
};



void dump_tls_compression_type (unsigned int compression_id )
{
int i;

    for (i = 0; i < (sizeof(tls_compressions)/sizeof(compression_string_t)); i++) {
        if (tls_compressions[i].compression_name_id == compression_id) {
            _debug_printf(TLS_INFO, " %s ", tls_compressions[i].compression_name );
            return;
        }
    }
    _debug_printf(TLS_INFO, " UNKNOWN ");
}



void dump_hex_bytes(unsigned char *pBuffer, int cnt )
{
int j = 0;
int k = 0;
int offst = 0;
int dump_debug = 0;

    while (j!=cnt)
    {
        k = ((cnt - j) > 16) ? 16 : cnt - j;
        dump_one_line(pBuffer+j, k, offst+j);
        j+=k;
    }
}

void dump_one_line(unsigned char *pBuffer, int nBytes, int startOffset)
{
    int i;
    unsigned char c;
    _debug_printf(TLS_INFO,"%08X --> ", startOffset);
    for (i = 0; i<nBytes; i++)
        _debug_printf(TLS_INFO,"%02X ",*(pBuffer+i));
    for (i = nBytes; i<16; i++)
        _debug_printf(TLS_INFO,"   ");
    
    for (i = 0; i<nBytes; i++)
    {
        c = *(pBuffer+i);
        _debug_printf(TLS_INFO,"%c",((c>=0x1f)&&(c<0x80)) ? c : 0x2e);
    }
    if (nBytes)
        _debug_printf(TLS_INFO,"\n");
    
}



