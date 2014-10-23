#include <libnet.h>

int main() {
    libnet_t *handle; /* Libnet handler */
    int packet_size; 
    char *device = "10.1.2.3"; /* device name */
    char *src_ip_str = "10.1.2.3"; /* Source IP String*/
    char *dst_ip_str = "10.1.2.2"; /* Destination IP String*/
    u_char src_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x02}; /* Source MAC */
    u_char dst_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01}; /* Destination MAC */
    u_long dst_ip, src_ip; 
    char error[LIBNET_ERRBUF_SIZE]; 
    libnet_ptag_t eth_tag, ip_tag, tcp_tag, tcp_op_tag; 
    u_short proto = IPPROTO_TCP; /* Transport layer protocol*/
    u_char payload[1400] = {0}; 
    u_long payload_s = 0; /* length of payload */

    /* Turn IP string to IP(little endian)*/
    dst_ip = libnet_name2addr4(handle, dst_ip_str, LIBNET_RESOLVE);
    src_ip = libnet_name2addr4(handle, src_ip_str, LIBNET_RESOLVE);

    /* init Libnet */
    if ( (handle = libnet_init(LIBNET_LINK, device, error)) == NULL ) {
        printf("libnet_init failure\n");
        return (-1);
    };

    strncpy(payload, "123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678123456781234567812345678", sizeof(payload)-1); /* load construct */
    payload_s = strlen(payload);
    printf("%lu\n",payload_s);

#if 0
    /* produce TCP */
    tcp_op_tag = libnet_build_tcp_options(
                payload,
                payload_s,
                handle,
                0
    );
    if (tcp_op_tag == -1) {
        printf("build_tcp_options failure\n");
        return (-2);
    };
#endif

    tcp_tag = libnet_build_tcp(
                30330,                    /* Source port */
                30331,                    /* Destination port */
                8888,                    /* sequence number */
                8889,                    /* acknowledgement number */
                TH_PUSH | TH_ACK,        /* Control flags */
                14600,                    /* window size */
                0,                        /* checksum */
                0,                        /* urgent pointer */
                LIBNET_TCP_H + payload_s, /* length */
                payload,                    /* payload */
                payload_s,                /* length of payload */
                handle,                    /* libnet handler */
                0                        /* protocol tag to modify an existing header, 0 to build a new one */
    );
    if (tcp_tag == -1) {
        printf("libnet_build_tcp failure\n");
        return (-3);
    };

    /* IP */
    ip_tag = libnet_build_ipv4(
        LIBNET_IPV4_H + LIBNET_TCP_H + payload_s, /* total length of the IP packet,*/
        0, /* tos */
        (u_short) libnet_get_prand(LIBNET_PRu16), /* IP identification number */
        0, /* fragmentation bits and offset */
        (u_int8_t)libnet_get_prand(LIBNET_PR8), /* time to live in the network */
        proto, /* upper layer protocol */
        0, /* checksum (0 for libnet to autofill) */
        src_ip, /* source IPv4 address (little endian) */
        dst_ip, /* destination IPv4 address (little endian) */
        NULL, /* payload */
        0, /* payload length*/
        handle, /* Libnet handler */
        0 /* protocol tag to modify an existing header, 0 to build a new one */
    );
    if (ip_tag == -1) {
        printf("libnet_build_ipv4 failure\n");
        return (-4);
    };

    /* MAC */
    eth_tag = libnet_build_ethernet(
        dst_mac, /* destination ethernet address */
        src_mac, /* source ethernet address */
        ETHERTYPE_IP, /* upper layer protocol type */
        NULL, /* payload */ 
        0, /* payload length */
        handle, /* Libnet handler*/
        0 /* protocol tag to modify an existing header, 0 to build a new one */ 
    );
    if (eth_tag == -1) {
        printf("libnet_build_ethernet failure\n");
        return (-5);
    };
for(;;)
    {
    packet_size = libnet_write(handle); /* packet out */
    //printf("%d\n", packet_size);
    printf("sending TCP packet!\n");
    //usleep(1);
}
libnet_destroy(handle); /* release the handler */

    return (0);
}
