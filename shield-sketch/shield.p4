/* -*- P4_16 -*- */

#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#elif __TARGET_TOFINO__ == 1
#include <tna.p4>
#else
#error This P4 program supports only Tofino Native Architecture
#endif

/*** C O N S T A N T S    A N D    T Y P E S ****/
typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;

enum bit<16> ether_type_t {
    IPV4        = 0x0800,
    ARP         = 0x0806,
    TPID        = 0x8100,
    IPV6        = 0x86DD,
    MPLS        = 0x8847,
    OVERFLOW    = 0x0F10,
    DECAY       = 0xDECA
}

enum bit<8> ip_protocol_t {
    ICMP    = 1,
    TCP     = 6,
    UDP     = 17
}

const MirrorType_t MIRROR_TYPE = 1;
const MirrorId_t MIRROR_SID = 10;

/********************************************************************
 *   Change these constants for different shapes and configuration  *
 ********************************************************************/
#define LAYER1_ENTRY_SIZE_EXP   16      // 2**16
#define LAYER2_ENTRY_SIZE_EXP   15      // 2**15
#define LAYER3_ENTRY_SIZE_EXP   14      // 2**14
#define LAYER1_BIT_SIZE         8       // 8 bits per task at layer 1
#define LAYER2_BIT_SIZE         16      // 16 bits per task at layer 2
#define LAYER3_BIT_SIZE         16      // 16 bits per task at layer 3
#define LAYER2_DECAY_BIT        1
#define LAYER3_DECAY_BIT        2
#define BLOCKLIST_SIZE          131072  // 2**17
#define THRESHOLD_ICMPQ         2000
#define THRESHOLD_UDP           2000
#define THRESHOLD_DNSQ          750
#define THRESHOLD_SYN           2000

#define GLOBAL_TIME1            33      // about 8 seconds
#define GLOBAL_TIME2            34      // about 16 seconds
#define GLOBAL_TIME3            35      // about 32 seconds

#define RECIRC_PORT             68
// #define PORT_A                  0
// #define PORT_B                  1
#define PORT_A                  44      // port 11 (enp216s0np0)
#define PORT_B                  36      // port 12 (enp59s0np0)
#define PORT_M                  192

#define PTF_TEST                0       // 1 is for PTF test, otherwise 0
#if PTF_TEST
#undef LAYER1_BIT_SIZE
#undef LAYER2_BIT_SIZE
#undef LAYER3_BIT_SIZE
#undef PORT_A
#undef PORT_B
#define LAYER1_BIT_SIZE         4       // 4 bits per task at layer 1
#define LAYER2_BIT_SIZE         4       // 4 bits per task at layer 2
#define LAYER3_BIT_SIZE         4       // 4 bits per task at layer 3
// #define PORT_A                  0
// #define PORT_B                  1
#define PORT_A                  64      // CPU Ethernet port
#define PORT_B                  66      // CPU Ethernet port
#endif
/********************************************************************
 *   Change these constants for different shapes and configuration  *
 ********************************************************************/

#define LAYER1_ENTRY_SIZE (1 << (LAYER1_ENTRY_SIZE_EXP))
#define LAYER2_ENTRY_SIZE (1 << (LAYER2_ENTRY_SIZE_EXP))
#define LAYER3_ENTRY_SIZE (1 << (LAYER3_ENTRY_SIZE_EXP))
#define LAYER1_TOTAL_BIT_SIZE ((LAYER1_BIT_SIZE)*4)
#define LAYER2_TOTAL_BIT_SIZE ((LAYER2_BIT_SIZE)*2)
#define LAYER3_TOTAL_BIT_SIZE ((LAYER3_BIT_SIZE)*2)

const bit<LAYER1_TOTAL_BIT_SIZE> LAYER1_ICMPQ   = 1 << ((LAYER1_BIT_SIZE)*3);
const bit<LAYER1_TOTAL_BIT_SIZE> LAYER1_UDP     = 1 << ((LAYER1_BIT_SIZE)*2);
const bit<LAYER1_TOTAL_BIT_SIZE> LAYER1_DNSQ    = 1 << ((LAYER1_BIT_SIZE)*1);
const bit<LAYER1_TOTAL_BIT_SIZE> LAYER1_SYN     = 1;
const bit<LAYER2_TOTAL_BIT_SIZE> LAYER2_ICMPQ   = 1 << (LAYER2_BIT_SIZE);
const bit<LAYER2_TOTAL_BIT_SIZE> LAYER2_UDP     = 1;
const bit<LAYER2_TOTAL_BIT_SIZE> LAYER2_DNSQ    = 1 << (LAYER2_BIT_SIZE);
const bit<LAYER2_TOTAL_BIT_SIZE> LAYER2_SYN     = 1;
const bit<LAYER3_TOTAL_BIT_SIZE> LAYER3_ICMPQ   = 1 << (LAYER3_BIT_SIZE);
const bit<LAYER3_TOTAL_BIT_SIZE> LAYER3_UDP     = 1;
const bit<LAYER3_TOTAL_BIT_SIZE> LAYER3_DNSQ    = 1 << (LAYER3_BIT_SIZE);
const bit<LAYER3_TOTAL_BIT_SIZE> LAYER3_SYN     = 1;

const bit<LAYER1_TOTAL_BIT_SIZE> LAYER1_DATA_3  = (1<<((LAYER1_BIT_SIZE)-1)) - 1;
const bit<LAYER1_TOTAL_BIT_SIZE> LAYER1_DATA_2  = LAYER1_DATA_3 << ((LAYER1_BIT_SIZE)*1);
const bit<LAYER1_TOTAL_BIT_SIZE> LAYER1_DATA_1  = LAYER1_DATA_3 << ((LAYER1_BIT_SIZE)*2);
const bit<LAYER1_TOTAL_BIT_SIZE> LAYER1_DATA_0  = LAYER1_DATA_3 << ((LAYER1_BIT_SIZE)*3);
const bit<LAYER1_TOTAL_BIT_SIZE> LAYER1_DATA    = LAYER1_DATA_3 + LAYER1_DATA_2 + LAYER1_DATA_1 + LAYER1_DATA_0;
const bit<LAYER2_TOTAL_BIT_SIZE> LAYER2_DATA_LO = (1<<((LAYER2_BIT_SIZE)-1)) - 1;
const bit<LAYER2_TOTAL_BIT_SIZE> LAYER2_DATA_HI = LAYER2_DATA_LO << (LAYER2_BIT_SIZE);
const bit<LAYER2_TOTAL_BIT_SIZE> LAYER2_DATA    = LAYER2_DATA_LO + LAYER2_DATA_HI;
const bit<LAYER3_TOTAL_BIT_SIZE> LAYER3_DATA_LO = (1<<((LAYER3_BIT_SIZE)-1)) - 1;
const bit<LAYER3_TOTAL_BIT_SIZE> LAYER3_DATA_HI = LAYER3_DATA_LO << (LAYER3_BIT_SIZE);
const bit<LAYER3_TOTAL_BIT_SIZE> LAYER3_DATA    = LAYER3_DATA_LO + LAYER3_DATA_HI;

const bit<LAYER2_TOTAL_BIT_SIZE> LAYER2_DECAY_DATA_LO   = (1<<((LAYER2_BIT_SIZE)-(LAYER2_DECAY_BIT))) - 1;
const bit<LAYER2_TOTAL_BIT_SIZE> LAYER2_DECAY_DATA_HI   = LAYER2_DECAY_DATA_LO << (LAYER2_BIT_SIZE);
const bit<LAYER2_TOTAL_BIT_SIZE> LAYER2_DECAY_DATA      = LAYER2_DECAY_DATA_LO + LAYER2_DECAY_DATA_HI;
const bit<LAYER3_TOTAL_BIT_SIZE> LAYER3_DECAY_DATA_LO   = (1<<((LAYER3_BIT_SIZE)-(LAYER3_DECAY_BIT))) - 1;
const bit<LAYER3_TOTAL_BIT_SIZE> LAYER3_DECAY_DATA_HI   = LAYER3_DECAY_DATA_LO << (LAYER3_BIT_SIZE);
const bit<LAYER3_TOTAL_BIT_SIZE> LAYER3_DECAY_DATA      = LAYER3_DECAY_DATA_LO + LAYER3_DECAY_DATA_HI;


/***** H E A D E R    D E F I N I T I O N S *****/
header ethernet_h {
    mac_addr_t      dst_addr;
    mac_addr_t      src_addr;
    ether_type_t    ether_type;
}

header overflow_h {
    bit<1> ingress_port_is_port_a;

    @padding bit<7> _padding;

    bit<16> ether_type;
}

header decay_update_h {
    bit<LAYER2_TOTAL_BIT_SIZE> layer2_arr0_tg0_decay;
    bit<LAYER2_TOTAL_BIT_SIZE> layer2_arr1_tg0_decay;
    bit<LAYER2_TOTAL_BIT_SIZE> layer2_arr0_tg1_decay;
    bit<LAYER2_TOTAL_BIT_SIZE> layer2_arr1_tg1_decay;

    bit<LAYER3_TOTAL_BIT_SIZE> layer3_arr0_tg0_decay;
    bit<LAYER3_TOTAL_BIT_SIZE> layer3_arr1_tg0_decay;
    bit<LAYER3_TOTAL_BIT_SIZE> layer3_arr0_tg1_decay;
    bit<LAYER3_TOTAL_BIT_SIZE> layer3_arr1_tg1_decay;

    bit<1>  layer2_arr0_is_decay;
    bit<1>  layer2_arr1_is_decay;
    bit<1>  layer3_arr0_is_decay;
    bit<1>  layer3_arr1_is_decay;

    bit<1> ingress_port_is_port_a;
    bit<1> ingress_port_is_management;

    @padding bit<((8 - ((LAYER2_TOTAL_BIT_SIZE*4+LAYER3_TOTAL_BIT_SIZE*4+4+2)%8)) % 8)> _padding;

    bit<16> ether_type;
}

header vlan_tag_h {
    bit<3>          pcp;
    bit<1>          cfi;
    bit<12>         vid;
    ether_type_t    ether_type;
}

header ipv4_h {
    bit<4>      version;
    bit<4>      ihl;
    bit<8>      diffserv;
    bit<16>     total_len;
    bit<16>     identification;
    bit<3>      flags;
    bit<13>     frag_offset;
    bit<8>      ttl;
    bit<8>      protocol;
    bit<16>     hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_length;
    bit<16> checksum;
}

header icmp_h {
    bit<8>  type_;
    bit<8>  code;
    bit<16> hdr_checksum;
}

header port_metadata {
    bit<8>  type;
    bit<32> f1;
    bit<16> f2;
    bit<8>  f3;
}

header upload_h {
	bit<16> upload_type;
}



/*************************************************
 ***** I N G R E S S    P R O C E S S I N G ******
 ************************************************/

/* All the headers we plan to process in ingress */
struct ingress_headers_t {
    ethernet_h      ethernet;
    overflow_h      overflow;
    decay_update_h  decay_update;
    vlan_tag_h      vlan_tag;
    ipv4_h          ipv4;
    icmp_h          icmp;
    tcp_h           tcp;
    udp_h           udp;
}

/*
 * All intermediate results that need to be available
 * to all P4-programmable components in ingress
 */
struct ingress_metadata_t {
    port_metadata       port_md;
    MirrorId_t          ing_mir_ses;
    upload_h            upload; // layer3_overflow_tag
    // Memory slicing result from reg_c2_layer1, reg_c2_layer2
    // 4 INM tasks in reg_c2_layer1 (32 bits), each have 8 bits.
    // 4 INM tasks in reg_c2_layer2_tg0 (32 bits) and reg_c2_layer2_tg1 (32 bits), each have 16 bits.
    // 4 INM tasks in reg_c2_layer3_tg0 (32 bits) and reg_c2_layer3_tg1 (32 bits), each have 16 bits.

    bit<(LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-3)> extracted_reg_c2_arr0_slice0;
    bit<(LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-3)> extracted_reg_c2_arr0_slice1;
    bit<(LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-3)> extracted_reg_c2_arr0_slice2;
    bit<(LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-3)> extracted_reg_c2_arr0_slice3;
    bit<(LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-3)> extracted_reg_c2_arr1_slice0;
    bit<(LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-3)> extracted_reg_c2_arr1_slice1;
    bit<(LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-3)> extracted_reg_c2_arr1_slice2;
    bit<(LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-3)> extracted_reg_c2_arr1_slice3;
}

parser IngressParser(packet_in          pkt,
    out ingress_headers_t               hdr,
    out ingress_metadata_t              md,
    out ingress_intrinsic_metadata_t    ig_intr_md)
{
    state start {
        /* Mandatory code required by Tofino Architecture */
        pkt.extract(ig_intr_md);
        transition parse_port_metadata;
    }

    state parse_port_metadata {
        md.port_md = port_metadata_unpack<port_metadata>(pkt);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ether_type_t.OVERFLOW   : parse_overflow;
            ether_type_t.DECAY      : parse_decay;
            ether_type_t.TPID       : parse_vlan_tag;
            ether_type_t.IPV4       : parse_ipv4;
            default                 : accept;   // In test, for global time change, packets with weird ether_type are periodically sent but dropped
        }
    }

    state parse_overflow {
        pkt.extract(hdr.overflow);
        transition select(hdr.overflow.ether_type) {
            ether_type_t.TPID   : parse_vlan_tag;
            ether_type_t.IPV4   : parse_ipv4;
            default             : reject;
        }
    }

    state parse_decay {
        pkt.extract(hdr.decay_update);
        transition select(hdr.decay_update.ether_type) {
            ether_type_t.TPID   : parse_vlan_tag;
            ether_type_t.IPV4   : parse_ipv4;
            default             : reject;
        }
    }

    state parse_vlan_tag {
        pkt.extract(hdr.vlan_tag);
        transition select(hdr.vlan_tag.ether_type) {
            ether_type_t.IPV4   : parse_ipv4;
            default             : reject;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
			ip_protocol_t.ICMP  : parse_icmp;
			ip_protocol_t.TCP   : parse_tcp;
			ip_protocol_t.UDP   : parse_udp;
			default             : accept;
		}
    }

    state parse_icmp {
        pkt.extract(hdr.icmp);
        transition accept;
    }

	state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

	state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }
}

/*********** M A T C H - A C T I O N ************/
control Ingress(
    /* User */
    inout ingress_headers_t                         hdr,
    inout ingress_metadata_t                        md,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t              ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t  ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md)
{
    /* Define variables, actions, and tables here */

    // Flags
    bit<1> is_blocked = 0;
    bit<1> icmpq_flag = 0;
    bit<1> udp_flag = 0;
    bit<1> dnsq_flag = 0;
    bit<1> syn_flag = 0;
    bit<1> block_request_arr0_slice0 = 0;
    bit<1> block_request_arr1_slice0 = 0;
    bit<1> block_request_arr0_slice1 = 0;
    bit<1> block_request_arr1_slice1 = 0;
    bit<1> block_request_arr0_slice2 = 0;
    bit<1> block_request_arr1_slice2 = 0;
    bit<1> block_request_arr0_slice3 = 0;
    bit<1> block_request_arr1_slice3 = 0;
    bit<1> block_request = 0;   // not used yet

    // Keys
    bit<32> reg_c2_key_a = 0;
    bit<32> reg_c2_key_b = 0;

    // Timestamp bits
    bit<1> global_time1 = 0;    // 8 seconds interval
    bit<1> global_time2 = 0;    // 16 seconds interval
    bit<1> global_time3 = 0;    // 32 seconds interval

    bit<1> reg_c_timer1_arr0_res = 0;
    bit<1> reg_c_timer1_arr1_res = 0;
    bit<1> reg_c_timer2_arr0_res = 0;
    bit<1> reg_c_timer2_arr1_res = 0;
    bit<1> reg_c_timer3_arr0_res = 0;
    bit<1> reg_c_timer3_arr1_res = 0;
    bit<1> reg_c_timer2_arr0_diff = 0;
    bit<1> reg_c_timer2_arr1_diff = 0;
    bit<1> reg_c_timer3_arr0_diff = 0;
    bit<1> reg_c_timer3_arr1_diff = 0;

    // Temporaral storage
    bit<LAYER1_TOTAL_BIT_SIZE> reg_c2_layer1_toupdate_value = 0;
    bit<LAYER2_TOTAL_BIT_SIZE> reg_c2_layer2_arr0_tg0_toupdate_value = 0;
    bit<LAYER2_TOTAL_BIT_SIZE> reg_c2_layer2_arr1_tg0_toupdate_value = 0;
    bit<LAYER2_TOTAL_BIT_SIZE> reg_c2_layer2_arr0_tg1_toupdate_value = 0;
    bit<LAYER2_TOTAL_BIT_SIZE> reg_c2_layer2_arr1_tg1_toupdate_value = 0;
    bit<LAYER3_TOTAL_BIT_SIZE> reg_c2_layer3_arr0_tg0_toupdate_value = 0;
    bit<LAYER3_TOTAL_BIT_SIZE> reg_c2_layer3_arr1_tg0_toupdate_value = 0;
    bit<LAYER3_TOTAL_BIT_SIZE> reg_c2_layer3_arr0_tg1_toupdate_value = 0;
    bit<LAYER3_TOTAL_BIT_SIZE> reg_c2_layer3_arr1_tg1_toupdate_value = 0;

    bit<LAYER1_TOTAL_BIT_SIZE> reg_c2_layer1_arr0_cur_res = 0;
    bit<LAYER1_TOTAL_BIT_SIZE> reg_c2_layer1_arr0_res = 0;
    bit<LAYER1_TOTAL_BIT_SIZE> reg_c2_layer1_arr1_cur_res = 0;
    bit<LAYER1_TOTAL_BIT_SIZE> reg_c2_layer1_arr1_res = 0;
    bit<LAYER2_TOTAL_BIT_SIZE> reg_c2_layer2_arr0_tg0_res = 0;
    bit<LAYER2_TOTAL_BIT_SIZE> reg_c2_layer2_arr0_tg1_res = 0;
    bit<LAYER2_TOTAL_BIT_SIZE> reg_c2_layer2_arr1_tg0_res = 0;
    bit<LAYER2_TOTAL_BIT_SIZE> reg_c2_layer2_arr1_tg1_res = 0;
    bit<LAYER3_TOTAL_BIT_SIZE> reg_c2_layer3_arr0_tg0_res = 0;
    bit<LAYER3_TOTAL_BIT_SIZE> reg_c2_layer3_arr0_tg1_res = 0;
    bit<LAYER3_TOTAL_BIT_SIZE> reg_c2_layer3_arr1_tg0_res = 0;
    bit<LAYER3_TOTAL_BIT_SIZE> reg_c2_layer3_arr1_tg1_res = 0;

    bit<1>  layer1_overflow_flag = 0;
    bit<1>  layer2_overflow_flag = 0;
    bit<9>  layer3_overflow_tag = 0;

    bit<8>  reg_c2_layer1_arr0_overflow_counter_res = 0;
    bit<8>  reg_c2_layer1_arr1_overflow_counter_res = 0;
    bit<8>  reg_c2_layer2_arr0_overflow_counter_res = 0;
    bit<8>  reg_c2_layer2_arr1_overflow_counter_res = 0;

    // Hash
    CRCPolynomial<bit<32>>(
        32w0x04C11DB7, // polynomial 
        true,          // reversed 
        false,         // use msb?
        false,         // extended?
        32w0xFFFFFFFF, // initial shift register value
        32w0xFFFFFFFF  // result xor
	) crc32;

    CRCPolynomial<bit<32>>(
        32w0x1EDC6F41,
        true,
        false,
        false,
        32w0xFFFFFFFF,
        32w0xFFFFFFFF
    ) crc32c;

    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, crc32) hash0;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, crc32c) hash1;

    // Register for get current time in CP,
    // Note that the current Python grpc API can not access ingress_prsr_md.global_tstamp
    // See DRV-6462
    Register<bit<1>, bit<1>>(1) reg_global_time1;
    RegisterAction<bit<1>, bit<1>, bit<1>>(reg_global_time1) global_time1_set0 = {
        void apply(inout bit<1> value, out bit<1> read_value){
            value = 0;
        }
    };
    RegisterAction<bit<1>, bit<1>, bit<1>>(reg_global_time1) global_time1_set1 = {
        void apply(inout bit<1> value, out bit<1> read_value){
            value = 1;
        }
    };

    Register<bit<1>, bit<1>>(1) reg_global_time2;
    RegisterAction<bit<1>, bit<1>, bit<1>>(reg_global_time2) global_time2_set0 = {
        void apply(inout bit<1> value, out bit<1> read_value){
            value = 0;
        }
    };
    RegisterAction<bit<1>, bit<1>, bit<1>>(reg_global_time2) global_time2_set1 = {
        void apply(inout bit<1> value, out bit<1> read_value){
            value = 1;
        }
    };

    Register<bit<1>, bit<1>>(1) reg_global_time3;
    RegisterAction<bit<1>, bit<1>, bit<1>>(reg_global_time3) global_time3_set0 = {
        void apply(inout bit<1> value, out bit<1> read_value){
            value = 0;
        }
    };
    RegisterAction<bit<1>, bit<1>, bit<1>>(reg_global_time3) global_time3_set1 = {
        void apply(inout bit<1> value, out bit<1> read_value){
            value = 1;
        }
    };

    Register<bit<1>, bit<LAYER1_ENTRY_SIZE_EXP>>(LAYER1_ENTRY_SIZE) reg_c_timer1_arr0;
    RegisterAction<bit<1>, bit<LAYER1_ENTRY_SIZE_EXP>, bit<1>>(reg_c_timer1_arr0) reg_c_timer1_arr0_update0 = {
        void apply(inout bit<1> value, out bit<1> read_value) {
            read_value = value;
            value = 0;
        }
    };
    RegisterAction<bit<1>, bit<LAYER1_ENTRY_SIZE_EXP>, bit<1>>(reg_c_timer1_arr0) reg_c_timer1_arr0_update1 = {
        void apply(inout bit<1> value, out bit<1> read_value) {
            read_value = value;
            value = 1;
        }
    };

    Register<bit<1>, bit<LAYER1_ENTRY_SIZE_EXP>>(LAYER1_ENTRY_SIZE) reg_c_timer1_arr1;
    RegisterAction<bit<1>, bit<LAYER1_ENTRY_SIZE_EXP>, bit<1>>(reg_c_timer1_arr1) reg_c_timer1_arr1_update0 = {
        void apply(inout bit<1> value, out bit<1> read_value) {
            read_value = value;
            value = 0;
        }
    };
    RegisterAction<bit<1>, bit<LAYER1_ENTRY_SIZE_EXP>, bit<1>>(reg_c_timer1_arr1) reg_c_timer1_arr1_update1 = {
        void apply(inout bit<1> value, out bit<1> read_value) {
            read_value = value;
            value = 1;
        }
    };

    Register<bit<1>, bit<LAYER2_ENTRY_SIZE_EXP>>(LAYER2_ENTRY_SIZE) reg_c_timer2_arr0;
    RegisterAction<bit<1>, bit<LAYER2_ENTRY_SIZE_EXP>, bit<1>>(reg_c_timer2_arr0) reg_c_timer2_arr0_update0 = {
        void apply(inout bit<1> value, out bit<1> read_value) {
            read_value = value;
            value = 0;
        }
    };
    RegisterAction<bit<1>, bit<LAYER2_ENTRY_SIZE_EXP>, bit<1>>(reg_c_timer2_arr0) reg_c_timer2_arr0_update1 = {
        void apply(inout bit<1> value, out bit<1> read_value) {
            read_value = value;
            value = 1;
        }
    };

    Register<bit<1>, bit<LAYER2_ENTRY_SIZE_EXP>>(LAYER2_ENTRY_SIZE) reg_c_timer2_arr1;
    RegisterAction<bit<1>, bit<LAYER2_ENTRY_SIZE_EXP>, bit<1>>(reg_c_timer2_arr1) reg_c_timer2_arr1_update0 = {
        void apply(inout bit<1> value, out bit<1> read_value) {
            read_value = value;
            value = 0;
        }
    };
    RegisterAction<bit<1>, bit<LAYER2_ENTRY_SIZE_EXP>, bit<1>>(reg_c_timer2_arr1) reg_c_timer2_arr1_update1 = {
        void apply(inout bit<1> value, out bit<1> read_value) {
            read_value = value;
            value = 1;
        }
    };

    Register<bit<1>, bit<LAYER3_ENTRY_SIZE_EXP>>(LAYER3_ENTRY_SIZE) reg_c_timer3_arr0;
    RegisterAction<bit<1>, bit<LAYER3_ENTRY_SIZE_EXP>, bit<1>>(reg_c_timer3_arr0) reg_c_timer3_arr0_update0 = {
        void apply(inout bit<1> value, out bit<1> read_value) {
            read_value = value;
            value = 0;
        }
    };
    RegisterAction<bit<1>, bit<LAYER3_ENTRY_SIZE_EXP>, bit<1>>(reg_c_timer3_arr0) reg_c_timer3_arr0_update1 = {
        void apply(inout bit<1> value, out bit<1> read_value) {
            read_value = value;
            value = 1;
        }
    };

    Register<bit<1>, bit<LAYER3_ENTRY_SIZE_EXP>>(LAYER3_ENTRY_SIZE) reg_c_timer3_arr1;
    RegisterAction<bit<1>, bit<LAYER3_ENTRY_SIZE_EXP>, bit<1>>(reg_c_timer3_arr1) reg_c_timer3_arr1_update0 = {
        void apply(inout bit<1> value, out bit<1> read_value) {
            read_value = value;
            value = 0;
        }
    };
    RegisterAction<bit<1>, bit<LAYER3_ENTRY_SIZE_EXP>, bit<1>>(reg_c_timer3_arr1) reg_c_timer3_arr1_update1 = {
        void apply(inout bit<1> value, out bit<1> read_value) {
            read_value = value;
            value = 1;
        }
    };

    // Registers and following RegisterActions
    Register<bit<LAYER1_TOTAL_BIT_SIZE>, bit<LAYER1_ENTRY_SIZE_EXP>>(LAYER1_ENTRY_SIZE) reg_c2_layer1_arr0_w1;
    RegisterAction<bit<LAYER1_TOTAL_BIT_SIZE>, bit<LAYER1_ENTRY_SIZE_EXP>, bit<LAYER1_TOTAL_BIT_SIZE>>(reg_c2_layer1_arr0_w1) reg_c2_layer1_arr0_w1_plus = {
        void apply(inout bit<LAYER1_TOTAL_BIT_SIZE> value, out bit<LAYER1_TOTAL_BIT_SIZE> read_value) {
            value = value + reg_c2_layer1_toupdate_value;
            read_value = value;
        }
    };
    RegisterAction<bit<LAYER1_TOTAL_BIT_SIZE>, bit<LAYER1_ENTRY_SIZE_EXP>, bit<LAYER1_TOTAL_BIT_SIZE>>(reg_c2_layer1_arr0_w1) reg_c2_layer1_arr0_w1_update = {
        void apply(inout bit<LAYER1_TOTAL_BIT_SIZE> value, out bit<LAYER1_TOTAL_BIT_SIZE> read_value) {
            value = reg_c2_layer1_toupdate_value;
            read_value = value;
        }
    };
    RegisterAction<bit<LAYER1_TOTAL_BIT_SIZE>, bit<LAYER1_ENTRY_SIZE_EXP>, bit<LAYER1_TOTAL_BIT_SIZE>>(reg_c2_layer1_arr0_w1) reg_c2_layer1_arr0_w1_setbit = {
        void apply(inout bit<LAYER1_TOTAL_BIT_SIZE> value, out bit<LAYER1_TOTAL_BIT_SIZE> read_value) {
            value = value & LAYER1_DATA;
            read_value = value;
        }
    };

    Register<bit<LAYER1_TOTAL_BIT_SIZE>, bit<LAYER1_ENTRY_SIZE_EXP>>(LAYER1_ENTRY_SIZE) reg_c2_layer1_arr0_w2;
    RegisterAction<bit<LAYER1_TOTAL_BIT_SIZE>, bit<LAYER1_ENTRY_SIZE_EXP>, bit<LAYER1_TOTAL_BIT_SIZE>>(reg_c2_layer1_arr0_w2) reg_c2_layer1_arr0_w2_plus = {
        void apply(inout bit<LAYER1_TOTAL_BIT_SIZE> value, out bit<LAYER1_TOTAL_BIT_SIZE> read_value) {
            value = value + reg_c2_layer1_toupdate_value;
            read_value = value;
        }
    };
    RegisterAction<bit<LAYER1_TOTAL_BIT_SIZE>, bit<LAYER1_ENTRY_SIZE_EXP>, bit<LAYER1_TOTAL_BIT_SIZE>>(reg_c2_layer1_arr0_w2) reg_c2_layer1_arr0_w2_update = {
        void apply(inout bit<LAYER1_TOTAL_BIT_SIZE> value, out bit<LAYER1_TOTAL_BIT_SIZE> read_value) {
            value = reg_c2_layer1_toupdate_value;
            read_value = value;
        }
    };
    RegisterAction<bit<LAYER1_TOTAL_BIT_SIZE>, bit<LAYER1_ENTRY_SIZE_EXP>, bit<LAYER1_TOTAL_BIT_SIZE>>(reg_c2_layer1_arr0_w2) reg_c2_layer1_arr0_w2_setbit = {
        void apply(inout bit<LAYER1_TOTAL_BIT_SIZE> value, out bit<LAYER1_TOTAL_BIT_SIZE> read_value) {
            value = value & LAYER1_DATA;
            read_value = value;
        }
    };

    Register<bit<LAYER1_TOTAL_BIT_SIZE>, bit<LAYER1_ENTRY_SIZE_EXP>>(LAYER1_ENTRY_SIZE) reg_c2_layer1_arr1_w1;
    RegisterAction<bit<LAYER1_TOTAL_BIT_SIZE>, bit<LAYER1_ENTRY_SIZE_EXP>, bit<LAYER1_TOTAL_BIT_SIZE>>(reg_c2_layer1_arr1_w1) reg_c2_layer1_arr1_w1_plus = {
        void apply(inout bit<LAYER1_TOTAL_BIT_SIZE> value, out bit<LAYER1_TOTAL_BIT_SIZE> read_value) {
            value = value + reg_c2_layer1_toupdate_value;
            read_value = value;
        }
    };
    RegisterAction<bit<LAYER1_TOTAL_BIT_SIZE>, bit<LAYER1_ENTRY_SIZE_EXP>, bit<LAYER1_TOTAL_BIT_SIZE>>(reg_c2_layer1_arr1_w1) reg_c2_layer1_arr1_w1_update = {
        void apply(inout bit<LAYER1_TOTAL_BIT_SIZE> value, out bit<LAYER1_TOTAL_BIT_SIZE> read_value) {
            value = reg_c2_layer1_toupdate_value;
            read_value = value;
        }
    };
    RegisterAction<bit<LAYER1_TOTAL_BIT_SIZE>, bit<LAYER1_ENTRY_SIZE_EXP>, bit<LAYER1_TOTAL_BIT_SIZE>>(reg_c2_layer1_arr1_w1) reg_c2_layer1_arr1_w1_setbit = {
        void apply(inout bit<LAYER1_TOTAL_BIT_SIZE> value, out bit<LAYER1_TOTAL_BIT_SIZE> read_value) {
            value = value & LAYER1_DATA;
            read_value = value;
        }
    };

    Register<bit<LAYER1_TOTAL_BIT_SIZE>, bit<LAYER1_ENTRY_SIZE_EXP>>(LAYER1_ENTRY_SIZE) reg_c2_layer1_arr1_w2;
    RegisterAction<bit<LAYER1_TOTAL_BIT_SIZE>, bit<LAYER1_ENTRY_SIZE_EXP>, bit<LAYER1_TOTAL_BIT_SIZE>>(reg_c2_layer1_arr1_w2) reg_c2_layer1_arr1_w2_plus = {
        void apply(inout bit<LAYER1_TOTAL_BIT_SIZE> value, out bit<LAYER1_TOTAL_BIT_SIZE> read_value) {
            value = value + reg_c2_layer1_toupdate_value;
            read_value = value;
        }
    };
    RegisterAction<bit<LAYER1_TOTAL_BIT_SIZE>, bit<LAYER1_ENTRY_SIZE_EXP>, bit<LAYER1_TOTAL_BIT_SIZE>>(reg_c2_layer1_arr1_w2) reg_c2_layer1_arr1_w2_update = {
        void apply(inout bit<LAYER1_TOTAL_BIT_SIZE> value, out bit<LAYER1_TOTAL_BIT_SIZE> read_value) {
            value = reg_c2_layer1_toupdate_value;
            read_value = value;
        }
    };
    RegisterAction<bit<LAYER1_TOTAL_BIT_SIZE>, bit<LAYER1_ENTRY_SIZE_EXP>, bit<LAYER1_TOTAL_BIT_SIZE>>(reg_c2_layer1_arr1_w2) reg_c2_layer1_arr1_w2_setbit = {
        void apply(inout bit<LAYER1_TOTAL_BIT_SIZE> value, out bit<LAYER1_TOTAL_BIT_SIZE> read_value) {
            value = value & LAYER1_DATA;
            read_value = value;
        }
    };

    Register<bit<LAYER2_TOTAL_BIT_SIZE>, bit<LAYER2_ENTRY_SIZE_EXP>>(LAYER2_ENTRY_SIZE) reg_c2_layer2_arr0_tg0;
    RegisterAction<bit<LAYER2_TOTAL_BIT_SIZE>, bit<LAYER2_ENTRY_SIZE_EXP>, bit<LAYER2_TOTAL_BIT_SIZE>>(reg_c2_layer2_arr0_tg0) reg_c2_layer2_arr0_tg0_plus = {
        void apply(inout bit<LAYER2_TOTAL_BIT_SIZE> value, out bit<LAYER2_TOTAL_BIT_SIZE> read_value) {
            value = value + reg_c2_layer2_arr0_tg0_toupdate_value;
            read_value = value;
        }
    };
    RegisterAction<bit<LAYER2_TOTAL_BIT_SIZE>, bit<LAYER2_ENTRY_SIZE_EXP>, bit<LAYER2_TOTAL_BIT_SIZE>>(reg_c2_layer2_arr0_tg0) reg_c2_layer2_arr0_tg0_decay = {
        void apply(inout bit<LAYER2_TOTAL_BIT_SIZE> value, out bit<LAYER2_TOTAL_BIT_SIZE> read_value) {
            value = reg_c2_layer2_arr0_tg0_toupdate_value;
            read_value = value;
        }
    };
    RegisterAction<bit<LAYER2_TOTAL_BIT_SIZE>, bit<LAYER2_ENTRY_SIZE_EXP>, bit<LAYER2_TOTAL_BIT_SIZE>>(reg_c2_layer2_arr0_tg0) reg_c2_layer2_arr0_tg0_setbit = {
        void apply(inout bit<LAYER2_TOTAL_BIT_SIZE> value, out bit<LAYER2_TOTAL_BIT_SIZE> read_value) {
            value = value & LAYER2_DATA;
            read_value = value;
        }
    };
    RegisterAction<bit<LAYER2_TOTAL_BIT_SIZE>, bit<LAYER2_ENTRY_SIZE_EXP>, bit<LAYER2_TOTAL_BIT_SIZE>>(reg_c2_layer2_arr0_tg0) reg_c2_layer2_arr0_tg0_read = {
        void apply(inout bit<LAYER2_TOTAL_BIT_SIZE> value, out bit<LAYER2_TOTAL_BIT_SIZE> read_value) {
            read_value = value;
        }
    };

    Register<bit<LAYER2_TOTAL_BIT_SIZE>, bit<LAYER2_ENTRY_SIZE_EXP>>(LAYER2_ENTRY_SIZE) reg_c2_layer2_arr0_tg1;
    RegisterAction<bit<LAYER2_TOTAL_BIT_SIZE>, bit<LAYER2_ENTRY_SIZE_EXP>, bit<LAYER2_TOTAL_BIT_SIZE>>(reg_c2_layer2_arr0_tg1) reg_c2_layer2_arr0_tg1_plus = {
        void apply(inout bit<LAYER2_TOTAL_BIT_SIZE> value, out bit<LAYER2_TOTAL_BIT_SIZE> read_value) {
            value = value + reg_c2_layer2_arr0_tg1_toupdate_value;
            read_value = value;
        }
    };
    RegisterAction<bit<LAYER2_TOTAL_BIT_SIZE>, bit<LAYER2_ENTRY_SIZE_EXP>, bit<LAYER2_TOTAL_BIT_SIZE>>(reg_c2_layer2_arr0_tg1) reg_c2_layer2_arr0_tg1_decay = {
        void apply(inout bit<LAYER2_TOTAL_BIT_SIZE> value, out bit<LAYER2_TOTAL_BIT_SIZE> read_value) {
            value = reg_c2_layer2_arr0_tg1_toupdate_value;
            read_value = value;
        }
    };
    RegisterAction<bit<LAYER2_TOTAL_BIT_SIZE>, bit<LAYER2_ENTRY_SIZE_EXP>, bit<LAYER2_TOTAL_BIT_SIZE>>(reg_c2_layer2_arr0_tg1) reg_c2_layer2_arr0_tg1_setbit = {
        void apply(inout bit<LAYER2_TOTAL_BIT_SIZE> value, out bit<LAYER2_TOTAL_BIT_SIZE> read_value) {
            value = value & LAYER2_DATA;
            read_value = value;
        }
    };
    RegisterAction<bit<LAYER2_TOTAL_BIT_SIZE>, bit<LAYER2_ENTRY_SIZE_EXP>, bit<LAYER2_TOTAL_BIT_SIZE>>(reg_c2_layer2_arr0_tg1) reg_c2_layer2_arr0_tg1_read = {
        void apply(inout bit<LAYER2_TOTAL_BIT_SIZE> value, out bit<LAYER2_TOTAL_BIT_SIZE> read_value) {
            read_value = value;
        }
    };

    Register<bit<LAYER2_TOTAL_BIT_SIZE>, bit<LAYER2_ENTRY_SIZE_EXP>>(LAYER2_ENTRY_SIZE) reg_c2_layer2_arr1_tg0;
    RegisterAction<bit<LAYER2_TOTAL_BIT_SIZE>, bit<LAYER2_ENTRY_SIZE_EXP>, bit<LAYER2_TOTAL_BIT_SIZE>>(reg_c2_layer2_arr1_tg0) reg_c2_layer2_arr1_tg0_plus = {
        void apply(inout bit<LAYER2_TOTAL_BIT_SIZE> value, out bit<LAYER2_TOTAL_BIT_SIZE> read_value) {
            value = value + reg_c2_layer2_arr1_tg0_toupdate_value;
            read_value = value;
        }
    };
    RegisterAction<bit<LAYER2_TOTAL_BIT_SIZE>, bit<LAYER2_ENTRY_SIZE_EXP>, bit<LAYER2_TOTAL_BIT_SIZE>>(reg_c2_layer2_arr1_tg0) reg_c2_layer2_arr1_tg0_decay = {
        void apply(inout bit<LAYER2_TOTAL_BIT_SIZE> value, out bit<LAYER2_TOTAL_BIT_SIZE> read_value) {
            value = reg_c2_layer2_arr1_tg0_toupdate_value;
            read_value = value;
        }
    };
    RegisterAction<bit<LAYER2_TOTAL_BIT_SIZE>, bit<LAYER2_ENTRY_SIZE_EXP>, bit<LAYER2_TOTAL_BIT_SIZE>>(reg_c2_layer2_arr1_tg0) reg_c2_layer2_arr1_tg0_setbit = {
        void apply(inout bit<LAYER2_TOTAL_BIT_SIZE> value, out bit<LAYER2_TOTAL_BIT_SIZE> read_value) {
            value = value & LAYER2_DATA;
            read_value = value;
        }
    };
    RegisterAction<bit<LAYER2_TOTAL_BIT_SIZE>, bit<LAYER2_ENTRY_SIZE_EXP>, bit<LAYER2_TOTAL_BIT_SIZE>>(reg_c2_layer2_arr1_tg0) reg_c2_layer2_arr1_tg0_read = {
        void apply(inout bit<LAYER2_TOTAL_BIT_SIZE> value, out bit<LAYER2_TOTAL_BIT_SIZE> read_value) {
            read_value = value;
        }
    };

    Register<bit<LAYER2_TOTAL_BIT_SIZE>, bit<LAYER2_ENTRY_SIZE_EXP>>(LAYER2_ENTRY_SIZE) reg_c2_layer2_arr1_tg1;
    RegisterAction<bit<LAYER2_TOTAL_BIT_SIZE>, bit<LAYER2_ENTRY_SIZE_EXP>, bit<LAYER2_TOTAL_BIT_SIZE>>(reg_c2_layer2_arr1_tg1) reg_c2_layer2_arr1_tg1_plus = {
        void apply(inout bit<LAYER2_TOTAL_BIT_SIZE> value, out bit<LAYER2_TOTAL_BIT_SIZE> read_value) {
            value = value + reg_c2_layer2_arr1_tg1_toupdate_value;
            read_value = value;
        }
    };
    RegisterAction<bit<LAYER2_TOTAL_BIT_SIZE>, bit<LAYER2_ENTRY_SIZE_EXP>, bit<LAYER2_TOTAL_BIT_SIZE>>(reg_c2_layer2_arr1_tg1) reg_c2_layer2_arr1_tg1_decay = {
        void apply(inout bit<LAYER2_TOTAL_BIT_SIZE> value, out bit<LAYER2_TOTAL_BIT_SIZE> read_value) {
            value = reg_c2_layer2_arr1_tg1_toupdate_value;
            read_value = value;
        }
    };
    RegisterAction<bit<LAYER2_TOTAL_BIT_SIZE>, bit<LAYER2_ENTRY_SIZE_EXP>, bit<LAYER2_TOTAL_BIT_SIZE>>(reg_c2_layer2_arr1_tg1) reg_c2_layer2_arr1_tg1_setbit = {
        void apply(inout bit<LAYER2_TOTAL_BIT_SIZE> value, out bit<LAYER2_TOTAL_BIT_SIZE> read_value) {
            value = value & LAYER2_DATA;
            read_value = value;
        }
    };
    RegisterAction<bit<LAYER2_TOTAL_BIT_SIZE>, bit<LAYER2_ENTRY_SIZE_EXP>, bit<LAYER2_TOTAL_BIT_SIZE>>(reg_c2_layer2_arr1_tg1) reg_c2_layer2_arr1_tg1_read = {
        void apply(inout bit<LAYER2_TOTAL_BIT_SIZE> value, out bit<LAYER2_TOTAL_BIT_SIZE> read_value) {
            read_value = value;
        }
    };

    Register<bit<LAYER3_TOTAL_BIT_SIZE>, bit<LAYER3_ENTRY_SIZE_EXP>>(LAYER3_ENTRY_SIZE) reg_c2_layer3_arr0_tg0;
    RegisterAction<bit<LAYER3_TOTAL_BIT_SIZE>, bit<LAYER3_ENTRY_SIZE_EXP>, bit<LAYER3_TOTAL_BIT_SIZE>>(reg_c2_layer3_arr0_tg0) reg_c2_layer3_arr0_tg0_plus = {
        void apply(inout bit<LAYER3_TOTAL_BIT_SIZE> value, out bit<LAYER3_TOTAL_BIT_SIZE> read_value) {
            value = value + reg_c2_layer3_arr0_tg0_toupdate_value;
            read_value = value;
        }
    };
    RegisterAction<bit<LAYER3_TOTAL_BIT_SIZE>, bit<LAYER3_ENTRY_SIZE_EXP>, bit<LAYER3_TOTAL_BIT_SIZE>>(reg_c2_layer3_arr0_tg0) reg_c2_layer3_arr0_tg0_decay = {
        void apply(inout bit<LAYER3_TOTAL_BIT_SIZE> value, out bit<LAYER3_TOTAL_BIT_SIZE> read_value) {
            value = reg_c2_layer3_arr0_tg0_toupdate_value;
            read_value = value;
        }
    };
    RegisterAction<bit<LAYER3_TOTAL_BIT_SIZE>, bit<LAYER3_ENTRY_SIZE_EXP>, bit<LAYER3_TOTAL_BIT_SIZE>>(reg_c2_layer3_arr0_tg0) reg_c2_layer3_arr0_tg0_setbit = {
        void apply(inout bit<LAYER3_TOTAL_BIT_SIZE> value, out bit<LAYER3_TOTAL_BIT_SIZE> read_value) {
            value = value & LAYER3_DATA;
            read_value = value;
        }
    };
    RegisterAction<bit<LAYER3_TOTAL_BIT_SIZE>, bit<LAYER3_ENTRY_SIZE_EXP>, bit<LAYER3_TOTAL_BIT_SIZE>>(reg_c2_layer3_arr0_tg0) reg_c2_layer3_arr0_tg0_read = {
        void apply(inout bit<LAYER3_TOTAL_BIT_SIZE> value, out bit<LAYER3_TOTAL_BIT_SIZE> read_value) {
            read_value = value;
        }
    };

    Register<bit<LAYER3_TOTAL_BIT_SIZE>, bit<LAYER3_ENTRY_SIZE_EXP>>(LAYER3_ENTRY_SIZE) reg_c2_layer3_arr0_tg1;
    RegisterAction<bit<LAYER3_TOTAL_BIT_SIZE>, bit<LAYER3_ENTRY_SIZE_EXP>, bit<LAYER3_TOTAL_BIT_SIZE>>(reg_c2_layer3_arr0_tg1) reg_c2_layer3_arr0_tg1_plus = {
        void apply(inout bit<LAYER3_TOTAL_BIT_SIZE> value, out bit<LAYER3_TOTAL_BIT_SIZE> read_value) {
            value = value + reg_c2_layer3_arr0_tg1_toupdate_value;
            read_value = value;
        }
    };
    RegisterAction<bit<LAYER3_TOTAL_BIT_SIZE>, bit<LAYER3_ENTRY_SIZE_EXP>, bit<LAYER3_TOTAL_BIT_SIZE>>(reg_c2_layer3_arr0_tg1) reg_c2_layer3_arr0_tg1_decay = {
        void apply(inout bit<LAYER3_TOTAL_BIT_SIZE> value, out bit<LAYER3_TOTAL_BIT_SIZE> read_value) {
            value = reg_c2_layer3_arr0_tg1_toupdate_value;
            read_value = value;
        }
    };
    RegisterAction<bit<LAYER3_TOTAL_BIT_SIZE>, bit<LAYER3_ENTRY_SIZE_EXP>, bit<LAYER3_TOTAL_BIT_SIZE>>(reg_c2_layer3_arr0_tg1) reg_c2_layer3_arr0_tg1_setbit = {
        void apply(inout bit<LAYER3_TOTAL_BIT_SIZE> value, out bit<LAYER3_TOTAL_BIT_SIZE> read_value) {
            value = value & LAYER3_DATA;
            read_value = value;
        }
    };
    RegisterAction<bit<LAYER3_TOTAL_BIT_SIZE>, bit<LAYER3_ENTRY_SIZE_EXP>, bit<LAYER3_TOTAL_BIT_SIZE>>(reg_c2_layer3_arr0_tg1) reg_c2_layer3_arr0_tg1_read = {
        void apply(inout bit<LAYER3_TOTAL_BIT_SIZE> value, out bit<LAYER3_TOTAL_BIT_SIZE> read_value) {
            read_value = value;
        }
    };

    Register<bit<LAYER3_TOTAL_BIT_SIZE>, bit<LAYER3_ENTRY_SIZE_EXP>>(LAYER3_ENTRY_SIZE) reg_c2_layer3_arr1_tg0;
    RegisterAction<bit<LAYER3_TOTAL_BIT_SIZE>, bit<LAYER3_ENTRY_SIZE_EXP>, bit<LAYER3_TOTAL_BIT_SIZE>>(reg_c2_layer3_arr1_tg0) reg_c2_layer3_arr1_tg0_plus = {
        void apply(inout bit<LAYER3_TOTAL_BIT_SIZE> value, out bit<LAYER3_TOTAL_BIT_SIZE> read_value) {
            value = value + reg_c2_layer3_arr1_tg0_toupdate_value;
            read_value = value;
        }
    };
    RegisterAction<bit<LAYER3_TOTAL_BIT_SIZE>, bit<LAYER3_ENTRY_SIZE_EXP>, bit<LAYER3_TOTAL_BIT_SIZE>>(reg_c2_layer3_arr1_tg0) reg_c2_layer3_arr1_tg0_decay = {
        void apply(inout bit<LAYER3_TOTAL_BIT_SIZE> value, out bit<LAYER3_TOTAL_BIT_SIZE> read_value) {
            value = reg_c2_layer3_arr1_tg0_toupdate_value;
            read_value = value;
        }
    };
    RegisterAction<bit<LAYER3_TOTAL_BIT_SIZE>, bit<LAYER3_ENTRY_SIZE_EXP>, bit<LAYER3_TOTAL_BIT_SIZE>>(reg_c2_layer3_arr1_tg0) reg_c2_layer3_arr1_tg0_setbit = {
        void apply(inout bit<LAYER3_TOTAL_BIT_SIZE> value, out bit<LAYER3_TOTAL_BIT_SIZE> read_value) {
            value = value & LAYER3_DATA;
            read_value = value;
        }
    };
    RegisterAction<bit<LAYER3_TOTAL_BIT_SIZE>, bit<LAYER3_ENTRY_SIZE_EXP>, bit<LAYER3_TOTAL_BIT_SIZE>>(reg_c2_layer3_arr1_tg0) reg_c2_layer3_arr1_tg0_read = {
        void apply(inout bit<LAYER3_TOTAL_BIT_SIZE> value, out bit<LAYER3_TOTAL_BIT_SIZE> read_value) {
            read_value = value;
        }
    };

    Register<bit<LAYER3_TOTAL_BIT_SIZE>, bit<LAYER3_ENTRY_SIZE_EXP>>(LAYER3_ENTRY_SIZE) reg_c2_layer3_arr1_tg1;
    RegisterAction<bit<LAYER3_TOTAL_BIT_SIZE>, bit<LAYER3_ENTRY_SIZE_EXP>, bit<LAYER3_TOTAL_BIT_SIZE>>(reg_c2_layer3_arr1_tg1) reg_c2_layer3_arr1_tg1_plus = {
        void apply(inout bit<LAYER3_TOTAL_BIT_SIZE> value, out bit<LAYER3_TOTAL_BIT_SIZE> read_value) {
            value = value + reg_c2_layer3_arr1_tg1_toupdate_value;
            read_value = value;
        }
    };
    RegisterAction<bit<LAYER3_TOTAL_BIT_SIZE>, bit<LAYER3_ENTRY_SIZE_EXP>, bit<LAYER3_TOTAL_BIT_SIZE>>(reg_c2_layer3_arr1_tg1) reg_c2_layer3_arr1_tg1_decay = {
        void apply(inout bit<LAYER3_TOTAL_BIT_SIZE> value, out bit<LAYER3_TOTAL_BIT_SIZE> read_value) {
            value = reg_c2_layer3_arr1_tg1_toupdate_value;
            read_value = value;
        }
    };
    RegisterAction<bit<LAYER3_TOTAL_BIT_SIZE>, bit<LAYER3_ENTRY_SIZE_EXP>, bit<LAYER3_TOTAL_BIT_SIZE>>(reg_c2_layer3_arr1_tg1) reg_c2_layer3_arr1_tg1_setbit = {
        void apply(inout bit<LAYER3_TOTAL_BIT_SIZE> value, out bit<LAYER3_TOTAL_BIT_SIZE> read_value) {
            value = value & LAYER3_DATA;
            read_value = value;
        }
    };
    RegisterAction<bit<LAYER3_TOTAL_BIT_SIZE>, bit<LAYER3_ENTRY_SIZE_EXP>, bit<LAYER3_TOTAL_BIT_SIZE>>(reg_c2_layer3_arr1_tg1) reg_c2_layer3_arr1_tg1_read = {
        void apply(inout bit<LAYER3_TOTAL_BIT_SIZE> value, out bit<LAYER3_TOTAL_BIT_SIZE> read_value) {
            read_value = value;
        }
    };

    Register<bit<8>, bit<LAYER1_ENTRY_SIZE_EXP>>(LAYER1_ENTRY_SIZE) reg_c2_layer1_arr0_overflow_counter;
    RegisterAction<bit<8>, bit<LAYER1_ENTRY_SIZE_EXP>, bit<8>>(reg_c2_layer1_arr0_overflow_counter) reg_c2_layer1_arr0_w1_overflow_counter_update = {
        void apply(inout bit<8> value, out bit<8> read_value) {
            value = value | (reg_c2_layer1_arr0_cur_res[(LAYER1_BIT_SIZE*4)-1:(LAYER1_BIT_SIZE*4)-1] \
                          ++ reg_c2_layer1_arr0_cur_res[(LAYER1_BIT_SIZE*3)-1:(LAYER1_BIT_SIZE*3)-1] \
                          ++ reg_c2_layer1_arr0_cur_res[(LAYER1_BIT_SIZE*2)-1:(LAYER1_BIT_SIZE*2)-1] \
                          ++ reg_c2_layer1_arr0_cur_res[(LAYER1_BIT_SIZE*1)-1:(LAYER1_BIT_SIZE*1)-1] ++ 4w0);
            read_value = value;
        }
    };
    RegisterAction<bit<8>, bit<LAYER1_ENTRY_SIZE_EXP>, bit<8>>(reg_c2_layer1_arr0_overflow_counter) reg_c2_layer1_arr0_w1_overflow_counter_reset = {
        void apply(inout bit<8> value, out bit<8> read_value) {
            value = (value & 8w0x0f) | (reg_c2_layer1_arr0_cur_res[(LAYER1_BIT_SIZE*4)-1:(LAYER1_BIT_SIZE*4)-1] \
                                     ++ reg_c2_layer1_arr0_cur_res[(LAYER1_BIT_SIZE*3)-1:(LAYER1_BIT_SIZE*3)-1] \
                                     ++ reg_c2_layer1_arr0_cur_res[(LAYER1_BIT_SIZE*2)-1:(LAYER1_BIT_SIZE*2)-1] \
                                     ++ reg_c2_layer1_arr0_cur_res[(LAYER1_BIT_SIZE*1)-1:(LAYER1_BIT_SIZE*1)-1] ++ 4w0);
            read_value = value;
        }
    };
    RegisterAction<bit<8>, bit<LAYER1_ENTRY_SIZE_EXP>, bit<8>>(reg_c2_layer1_arr0_overflow_counter) reg_c2_layer1_arr0_w2_overflow_counter_update = {
        void apply(inout bit<8> value, out bit<8> read_value) {
            value = value | (4w0 ++ reg_c2_layer1_arr0_cur_res[(LAYER1_BIT_SIZE*4)-1:(LAYER1_BIT_SIZE*4)-1] \
                                 ++ reg_c2_layer1_arr0_cur_res[(LAYER1_BIT_SIZE*3)-1:(LAYER1_BIT_SIZE*3)-1] \
                                 ++ reg_c2_layer1_arr0_cur_res[(LAYER1_BIT_SIZE*2)-1:(LAYER1_BIT_SIZE*2)-1] \
                                 ++ reg_c2_layer1_arr0_cur_res[(LAYER1_BIT_SIZE*1)-1:(LAYER1_BIT_SIZE*1)-1]);
            read_value = value;
        }
    };
    RegisterAction<bit<8>, bit<LAYER1_ENTRY_SIZE_EXP>, bit<8>>(reg_c2_layer1_arr0_overflow_counter) reg_c2_layer1_arr0_w2_overflow_counter_reset = {
        void apply(inout bit<8> value, out bit<8> read_value) {
            value = (value & 8w0xf0) | (4w0 ++ reg_c2_layer1_arr0_cur_res[(LAYER1_BIT_SIZE*4)-1:(LAYER1_BIT_SIZE*4)-1] \
                                            ++ reg_c2_layer1_arr0_cur_res[(LAYER1_BIT_SIZE*3)-1:(LAYER1_BIT_SIZE*3)-1] \
                                            ++ reg_c2_layer1_arr0_cur_res[(LAYER1_BIT_SIZE*2)-1:(LAYER1_BIT_SIZE*2)-1] \
                                            ++ reg_c2_layer1_arr0_cur_res[(LAYER1_BIT_SIZE*1)-1:(LAYER1_BIT_SIZE*1)-1]);
            read_value = value;
        }
    };

    Register<bit<8>, bit<LAYER1_ENTRY_SIZE_EXP>>(LAYER1_ENTRY_SIZE) reg_c2_layer1_arr1_overflow_counter;
    RegisterAction<bit<8>, bit<LAYER1_ENTRY_SIZE_EXP>, bit<8>>(reg_c2_layer1_arr1_overflow_counter) reg_c2_layer1_arr1_w1_overflow_counter_update = {
        void apply(inout bit<8> value, out bit<8> read_value) {
            value = value | (reg_c2_layer1_arr1_cur_res[(LAYER1_BIT_SIZE*4)-1:(LAYER1_BIT_SIZE*4)-1] \
                          ++ reg_c2_layer1_arr1_cur_res[(LAYER1_BIT_SIZE*3)-1:(LAYER1_BIT_SIZE*3)-1] \
                          ++ reg_c2_layer1_arr1_cur_res[(LAYER1_BIT_SIZE*2)-1:(LAYER1_BIT_SIZE*2)-1] \
                          ++ reg_c2_layer1_arr1_cur_res[(LAYER1_BIT_SIZE*1)-1:(LAYER1_BIT_SIZE*1)-1] ++ 4w0);
            read_value = value;
        }
    };
    RegisterAction<bit<8>, bit<LAYER1_ENTRY_SIZE_EXP>, bit<8>>(reg_c2_layer1_arr1_overflow_counter) reg_c2_layer1_arr1_w1_overflow_counter_reset = {
        void apply(inout bit<8> value, out bit<8> read_value) {
            value = (value & 8w0x0f) | (reg_c2_layer1_arr1_cur_res[(LAYER1_BIT_SIZE*4)-1:(LAYER1_BIT_SIZE*4)-1] \
                                     ++ reg_c2_layer1_arr1_cur_res[(LAYER1_BIT_SIZE*3)-1:(LAYER1_BIT_SIZE*3)-1] \
                                     ++ reg_c2_layer1_arr1_cur_res[(LAYER1_BIT_SIZE*2)-1:(LAYER1_BIT_SIZE*2)-1] \
                                     ++ reg_c2_layer1_arr1_cur_res[(LAYER1_BIT_SIZE*1)-1:(LAYER1_BIT_SIZE*1)-1] ++ 4w0);
            read_value = value;
        }
    };
    RegisterAction<bit<8>, bit<LAYER1_ENTRY_SIZE_EXP>, bit<8>>(reg_c2_layer1_arr1_overflow_counter) reg_c2_layer1_arr1_w2_overflow_counter_update = {
        void apply(inout bit<8> value, out bit<8> read_value) {
            value = value | (4w0 ++ reg_c2_layer1_arr1_cur_res[(LAYER1_BIT_SIZE*4)-1:(LAYER1_BIT_SIZE*4)-1] \
                                 ++ reg_c2_layer1_arr1_cur_res[(LAYER1_BIT_SIZE*3)-1:(LAYER1_BIT_SIZE*3)-1] \
                                 ++ reg_c2_layer1_arr1_cur_res[(LAYER1_BIT_SIZE*2)-1:(LAYER1_BIT_SIZE*2)-1] \
                                 ++ reg_c2_layer1_arr1_cur_res[(LAYER1_BIT_SIZE*1)-1:(LAYER1_BIT_SIZE*1)-1]);
            read_value = value;
        }
    };
    RegisterAction<bit<8>, bit<LAYER1_ENTRY_SIZE_EXP>, bit<8>>(reg_c2_layer1_arr1_overflow_counter) reg_c2_layer1_arr1_w2_overflow_counter_reset = {
        void apply(inout bit<8> value, out bit<8> read_value) {
            value = (value & 8w0xf0) | (4w0 ++ reg_c2_layer1_arr1_cur_res[(LAYER1_BIT_SIZE*4)-1:(LAYER1_BIT_SIZE*4)-1] \
                                            ++ reg_c2_layer1_arr1_cur_res[(LAYER1_BIT_SIZE*3)-1:(LAYER1_BIT_SIZE*3)-1] \
                                            ++ reg_c2_layer1_arr1_cur_res[(LAYER1_BIT_SIZE*2)-1:(LAYER1_BIT_SIZE*2)-1] \
                                            ++ reg_c2_layer1_arr1_cur_res[(LAYER1_BIT_SIZE*1)-1:(LAYER1_BIT_SIZE*1)-1]);
            read_value = value;
        }
    };

    Register<bit<8>, bit<LAYER2_ENTRY_SIZE_EXP>>(LAYER2_ENTRY_SIZE) reg_c2_layer2_arr0_overflow_counter;
    RegisterAction<bit<8>, bit<LAYER2_ENTRY_SIZE_EXP>, bit<8>>(reg_c2_layer2_arr0_overflow_counter) reg_c2_layer2_arr0_w1_overflow_counter_update = {
        void apply(inout bit<8> value, out bit<8> read_value) {
            value = value | (reg_c2_layer2_arr0_tg0_res[(LAYER2_BIT_SIZE*2)-1:(LAYER2_BIT_SIZE*2)-1] \
                          ++ reg_c2_layer2_arr0_tg0_res[(LAYER2_BIT_SIZE*1)-1:(LAYER2_BIT_SIZE*1)-1] \
                          ++ reg_c2_layer2_arr0_tg1_res[(LAYER2_BIT_SIZE*2)-1:(LAYER2_BIT_SIZE*2)-1] \
                          ++ reg_c2_layer2_arr0_tg1_res[(LAYER2_BIT_SIZE*1)-1:(LAYER2_BIT_SIZE*1)-1] ++ 4w0);
            read_value = value;
        }
    };
    RegisterAction<bit<8>, bit<LAYER2_ENTRY_SIZE_EXP>, bit<8>>(reg_c2_layer2_arr0_overflow_counter) reg_c2_layer2_arr0_w1_overflow_counter_reset = {
        void apply(inout bit<8> value, out bit<8> read_value) {
            value = (value & 8w0x0f) | (reg_c2_layer2_arr0_tg0_res[(LAYER2_BIT_SIZE*2)-1:(LAYER2_BIT_SIZE*2)-1] \
                                     ++ reg_c2_layer2_arr0_tg0_res[(LAYER2_BIT_SIZE*1)-1:(LAYER2_BIT_SIZE*1)-1] \
                                     ++ reg_c2_layer2_arr0_tg1_res[(LAYER2_BIT_SIZE*2)-1:(LAYER2_BIT_SIZE*2)-1] \
                                     ++ reg_c2_layer2_arr0_tg1_res[(LAYER2_BIT_SIZE*1)-1:(LAYER2_BIT_SIZE*1)-1] ++ 4w0);
            read_value = value;
        }
    };
    RegisterAction<bit<8>, bit<LAYER2_ENTRY_SIZE_EXP>, bit<8>>(reg_c2_layer2_arr0_overflow_counter) reg_c2_layer2_arr0_w2_overflow_counter_update = {
        void apply(inout bit<8> value, out bit<8> read_value) {
            value = value | (4w0 ++ reg_c2_layer2_arr0_tg0_res[(LAYER2_BIT_SIZE*2)-1:(LAYER2_BIT_SIZE*2)-1] \
                                 ++ reg_c2_layer2_arr0_tg0_res[(LAYER2_BIT_SIZE*1)-1:(LAYER2_BIT_SIZE*1)-1] \
                                 ++ reg_c2_layer2_arr0_tg1_res[(LAYER2_BIT_SIZE*2)-1:(LAYER2_BIT_SIZE*2)-1] \
                                 ++ reg_c2_layer2_arr0_tg1_res[(LAYER2_BIT_SIZE*1)-1:(LAYER2_BIT_SIZE*1)-1]);
            read_value = value;
        }
    };
    RegisterAction<bit<8>, bit<LAYER2_ENTRY_SIZE_EXP>, bit<8>>(reg_c2_layer2_arr0_overflow_counter) reg_c2_layer2_arr0_w2_overflow_counter_reset = {
        void apply(inout bit<8> value, out bit<8> read_value) {
            value = (value & 8w0xf0) | (4w0 ++ reg_c2_layer2_arr0_tg0_res[(LAYER2_BIT_SIZE*2)-1:(LAYER2_BIT_SIZE*2)-1] \
                                            ++ reg_c2_layer2_arr0_tg0_res[(LAYER2_BIT_SIZE*1)-1:(LAYER2_BIT_SIZE*1)-1] \
                                            ++ reg_c2_layer2_arr0_tg1_res[(LAYER2_BIT_SIZE*2)-1:(LAYER2_BIT_SIZE*2)-1] \
                                            ++ reg_c2_layer2_arr0_tg1_res[(LAYER2_BIT_SIZE*1)-1:(LAYER2_BIT_SIZE*1)-1]);
            read_value = value;
        }
    };

    Register<bit<8>, bit<LAYER2_ENTRY_SIZE_EXP>>(LAYER2_ENTRY_SIZE) reg_c2_layer2_arr1_overflow_counter;
    RegisterAction<bit<8>, bit<LAYER2_ENTRY_SIZE_EXP>, bit<8>>(reg_c2_layer2_arr1_overflow_counter) reg_c2_layer2_arr1_w1_overflow_counter_update = {
        void apply(inout bit<8> value, out bit<8> read_value) {
            value = value | (reg_c2_layer2_arr1_tg0_res[(LAYER2_BIT_SIZE*2)-1:(LAYER2_BIT_SIZE*2)-1] \
                          ++ reg_c2_layer2_arr1_tg0_res[(LAYER2_BIT_SIZE*1)-1:(LAYER2_BIT_SIZE*1)-1] \
                          ++ reg_c2_layer2_arr1_tg1_res[(LAYER2_BIT_SIZE*2)-1:(LAYER2_BIT_SIZE*2)-1] \
                          ++ reg_c2_layer2_arr1_tg1_res[(LAYER2_BIT_SIZE*1)-1:(LAYER2_BIT_SIZE*1)-1] ++ 4w0);
            read_value = value;
        }
    };
    RegisterAction<bit<8>, bit<LAYER2_ENTRY_SIZE_EXP>, bit<8>>(reg_c2_layer2_arr1_overflow_counter) reg_c2_layer2_arr1_w1_overflow_counter_reset = {
        void apply(inout bit<8> value, out bit<8> read_value) {
            value = (value & 8w0x0f) | (reg_c2_layer2_arr1_tg0_res[(LAYER2_BIT_SIZE*2)-1:(LAYER2_BIT_SIZE*2)-1] \
                                     ++ reg_c2_layer2_arr1_tg0_res[(LAYER2_BIT_SIZE*1)-1:(LAYER2_BIT_SIZE*1)-1] \
                                     ++ reg_c2_layer2_arr1_tg1_res[(LAYER2_BIT_SIZE*2)-1:(LAYER2_BIT_SIZE*2)-1] \
                                     ++ reg_c2_layer2_arr1_tg1_res[(LAYER2_BIT_SIZE*1)-1:(LAYER2_BIT_SIZE*1)-1] ++ 4w0);
            read_value = value;
        }
    };
    RegisterAction<bit<8>, bit<LAYER2_ENTRY_SIZE_EXP>, bit<8>>(reg_c2_layer2_arr1_overflow_counter) reg_c2_layer2_arr1_w2_overflow_counter_update = {
        void apply(inout bit<8> value, out bit<8> read_value) {
            value = value | (4w0 ++ reg_c2_layer2_arr1_tg0_res[(LAYER2_BIT_SIZE*2)-1:(LAYER2_BIT_SIZE*2)-1] \
                                 ++ reg_c2_layer2_arr1_tg0_res[(LAYER2_BIT_SIZE*1)-1:(LAYER2_BIT_SIZE*1)-1] \
                                 ++ reg_c2_layer2_arr1_tg1_res[(LAYER2_BIT_SIZE*2)-1:(LAYER2_BIT_SIZE*2)-1] \
                                 ++ reg_c2_layer2_arr1_tg1_res[(LAYER2_BIT_SIZE*1)-1:(LAYER2_BIT_SIZE*1)-1]);
            read_value = value;
        }
    };
    RegisterAction<bit<8>, bit<LAYER2_ENTRY_SIZE_EXP>, bit<8>>(reg_c2_layer2_arr1_overflow_counter) reg_c2_layer2_arr1_w2_overflow_counter_reset = {
        void apply(inout bit<8> value, out bit<8> read_value) {
            value = (value & 8w0xf0) | (4w0 ++ reg_c2_layer2_arr1_tg0_res[(LAYER2_BIT_SIZE*2)-1:(LAYER2_BIT_SIZE*2)-1] \
                                            ++ reg_c2_layer2_arr1_tg0_res[(LAYER2_BIT_SIZE*1)-1:(LAYER2_BIT_SIZE*1)-1] \
                                            ++ reg_c2_layer2_arr1_tg1_res[(LAYER2_BIT_SIZE*2)-1:(LAYER2_BIT_SIZE*2)-1] \
                                            ++ reg_c2_layer2_arr1_tg1_res[(LAYER2_BIT_SIZE*1)-1:(LAYER2_BIT_SIZE*1)-1]);
            read_value = value;
        }
    };

    action drop() {
        is_blocked = 1;
        ig_dprsr_md.drop_ctl = 1;
    }

    table check_blocklist {
        key = {
            hdr.ipv4.src_addr   : exact;
            hdr.ipv4.dst_addr   : exact;
        }
        actions = {
            drop;
        }
        size = BLOCKLIST_SIZE;
    }

    action check_icmpq_setflag() {
	    icmpq_flag = 1;
    }

    table check_icmpq_table {
        key = {
            hdr.icmp.isValid()  : exact;
            hdr.icmp.type_      : exact;
        }
        actions = {
            check_icmpq_setflag;
        }
        size = 1;
    }

    action check_udp_setflag() {
        udp_flag = 1;
    }

    table check_udp_table {
        key = {
            hdr.udp.isValid()   : exact;
        }
        actions = {
            check_udp_setflag;
        }
        size = 1;
    }

    action check_dnsq_setflag() {
        dnsq_flag = 1;
    }

    table check_dnsq_table {
        key = {
            hdr.udp.isValid()   : exact;
            hdr.udp.dst_port    : exact;
        }
        actions = {
            check_dnsq_setflag;
        }
        size = 1;
    }

    action check_syn_setflag() {
        syn_flag = 1;
    }

    table check_syn_table {
        key = {
            hdr.tcp.isValid()   : exact;
            hdr.tcp.flags       : exact;
        }
        actions = {
            check_syn_setflag;
        }
        size = 1;
    }

    action global_time1_set0_action() {
        global_time1_set0.execute(0);
    }

    action global_time1_set1_action() {
        global_time1_set1.execute(0);
    }

    table reg_global_time1_set_table {
        key = {
            global_time1    : exact;
        }
        actions = {
            global_time1_set0_action;
            global_time1_set1_action;
        }
    }

    action global_time2_set0_action() {
        global_time2_set0.execute(0);
    }

    action global_time2_set1_action() {
        global_time2_set1.execute(0);
    }

    table reg_global_time2_set_table {
        key = {
            global_time2    : exact;
        }
        actions = {
            global_time2_set0_action;
            global_time2_set1_action;
        }
    }

    action global_time3_set0_action() {
        global_time3_set0.execute(0);
    }

    action global_time3_set1_action() {
        global_time3_set1.execute(0);
    }

    table reg_global_time3_set_table {
        key = {
            global_time3    : exact;
        }
        actions = {
            global_time3_set0_action;
            global_time3_set1_action;
        }
    }

    action reg_c_timer1_arr0_update0_action() {
        reg_c_timer1_arr0_res = reg_c_timer1_arr0_update0.execute(reg_c2_key_a[LAYER1_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c_timer1_arr0_update1_action() {
        reg_c_timer1_arr0_res = reg_c_timer1_arr0_update1.execute(reg_c2_key_a[LAYER1_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c_timer1_arr1_update0_action() {
        reg_c_timer1_arr1_res = reg_c_timer1_arr1_update0.execute(reg_c2_key_b[LAYER1_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c_timer1_arr1_update1_action() {
        reg_c_timer1_arr1_res = reg_c_timer1_arr1_update1.execute(reg_c2_key_b[LAYER1_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c_timer2_arr0_update0_action() {
        reg_c_timer2_arr0_res = reg_c_timer2_arr0_update0.execute(reg_c2_key_a[LAYER2_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c_timer2_arr0_update1_action() {
        reg_c_timer2_arr0_res = reg_c_timer2_arr0_update1.execute(reg_c2_key_a[LAYER2_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c_timer2_arr1_update0_action() {
        reg_c_timer2_arr1_res = reg_c_timer2_arr1_update0.execute(reg_c2_key_b[LAYER2_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c_timer2_arr1_update1_action() {
        reg_c_timer2_arr1_res = reg_c_timer2_arr1_update1.execute(reg_c2_key_b[LAYER2_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c_timer3_arr0_update0_action() {
        reg_c_timer3_arr0_res = reg_c_timer3_arr0_update0.execute(reg_c2_key_a[LAYER3_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c_timer3_arr0_update1_action() {
        reg_c_timer3_arr0_res = reg_c_timer3_arr0_update1.execute(reg_c2_key_a[LAYER3_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c_timer3_arr1_update0_action() {
        reg_c_timer3_arr1_res = reg_c_timer3_arr1_update0.execute(reg_c2_key_b[LAYER3_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c_timer3_arr1_update1_action() {
        reg_c_timer3_arr1_res = reg_c_timer3_arr1_update1.execute(reg_c2_key_b[LAYER3_ENTRY_SIZE_EXP-1:0]);
    }

    table reg_c_timer1_arr0_table {
        key = {
            global_time1    : exact;
        }
        actions = {
            reg_c_timer1_arr0_update0_action;
            reg_c_timer1_arr0_update1_action;
        }
    }

    table reg_c_timer1_arr1_table {
        key = {
            global_time1    : exact;
        }
        actions = {
            reg_c_timer1_arr1_update0_action;
            reg_c_timer1_arr1_update1_action;
        }
    }

    table reg_c_timer2_arr0_table {
        key = {
            global_time2    : exact;
        }
        actions = {
            reg_c_timer2_arr0_update0_action;
            reg_c_timer2_arr0_update1_action;
        }
    }

    table reg_c_timer2_arr1_table {
        key = {
            global_time2    : exact;
        }
        actions = {
            reg_c_timer2_arr1_update0_action;
            reg_c_timer2_arr1_update1_action;
        }
    }

    table reg_c_timer3_arr0_table {
        key = {
            global_time3    : exact;
        }
        actions = {
            reg_c_timer3_arr0_update0_action;
            reg_c_timer3_arr0_update1_action;
        }
    }

    table reg_c_timer3_arr1_table {
        key = {
            global_time3    : exact;
        }
        actions = {
            reg_c_timer3_arr1_update0_action;
            reg_c_timer3_arr1_update1_action;
        }
    }

    action reg_c2_layer1_merge(bit<LAYER1_TOTAL_BIT_SIZE> slices) {
        reg_c2_layer1_toupdate_value = slices;
    }

    table reg_c2_layer1_dyn_table {
        key = {
            icmpq_flag  : exact;
            udp_flag    : exact;
            dnsq_flag   : exact;
            syn_flag    : exact;
        }
        actions = {
            reg_c2_layer1_merge;
        }
    }

    action reg_c2_layer2_arr0_merge(bit<LAYER2_TOTAL_BIT_SIZE> slices0, bit<LAYER2_TOTAL_BIT_SIZE> slices1) {
        reg_c2_layer2_arr0_tg0_toupdate_value = slices0;
        reg_c2_layer2_arr0_tg1_toupdate_value = slices1;
    }

    action reg_c2_layer2_arr0_decay() {
        reg_c2_layer2_arr0_tg0_toupdate_value = hdr.decay_update.layer2_arr0_tg0_decay & LAYER2_DECAY_DATA;
        reg_c2_layer2_arr0_tg1_toupdate_value = hdr.decay_update.layer2_arr0_tg1_decay & LAYER2_DECAY_DATA;
    }

    table reg_c2_layer2_arr0_dyn_table {
        key = {
            reg_c_timer2_arr0_diff                                                  : exact;
            reg_c2_layer1_arr0_cur_res[(LAYER1_BIT_SIZE*4)-1:(LAYER1_BIT_SIZE*4)-1] : exact;
            reg_c2_layer1_arr0_cur_res[(LAYER1_BIT_SIZE*3)-1:(LAYER1_BIT_SIZE*3)-1] : exact;
            reg_c2_layer1_arr0_cur_res[(LAYER1_BIT_SIZE*2)-1:(LAYER1_BIT_SIZE*2)-1] : exact;
            reg_c2_layer1_arr0_cur_res[(LAYER1_BIT_SIZE*1)-1:(LAYER1_BIT_SIZE*1)-1] : exact;
            hdr.decay_update.isValid()                                              : exact;
        }
        actions = {
            reg_c2_layer2_arr0_merge;
            reg_c2_layer2_arr0_decay;
        }
    }

    action reg_c2_layer2_arr1_merge(bit<LAYER2_TOTAL_BIT_SIZE> slices0, bit<LAYER2_TOTAL_BIT_SIZE> slices1) {
        reg_c2_layer2_arr1_tg0_toupdate_value = slices0;
        reg_c2_layer2_arr1_tg1_toupdate_value = slices1;
    }

    action reg_c2_layer2_arr1_decay() {
        reg_c2_layer2_arr1_tg0_toupdate_value = hdr.decay_update.layer2_arr1_tg0_decay & LAYER2_DECAY_DATA;
        reg_c2_layer2_arr1_tg1_toupdate_value = hdr.decay_update.layer2_arr1_tg1_decay & LAYER2_DECAY_DATA;
    }

    table reg_c2_layer2_arr1_dyn_table {
        key = {
            reg_c_timer2_arr1_diff                                                  : exact;
            reg_c2_layer1_arr1_cur_res[(LAYER1_BIT_SIZE*4)-1:(LAYER1_BIT_SIZE*4)-1] : exact;
            reg_c2_layer1_arr1_cur_res[(LAYER1_BIT_SIZE*3)-1:(LAYER1_BIT_SIZE*3)-1] : exact;
            reg_c2_layer1_arr1_cur_res[(LAYER1_BIT_SIZE*2)-1:(LAYER1_BIT_SIZE*2)-1] : exact;
            reg_c2_layer1_arr1_cur_res[(LAYER1_BIT_SIZE*1)-1:(LAYER1_BIT_SIZE*1)-1] : exact;
            hdr.decay_update.isValid()                                              : exact;
        }
        actions = {
            reg_c2_layer2_arr1_merge;
            reg_c2_layer2_arr1_decay;
        }
    }

    action reg_c2_layer3_arr0_merge(bit<LAYER3_TOTAL_BIT_SIZE> slices0, bit<LAYER3_TOTAL_BIT_SIZE> slices1) {
        reg_c2_layer3_arr0_tg0_toupdate_value = slices0;
        reg_c2_layer3_arr0_tg1_toupdate_value = slices1;
    }

    action reg_c2_layer3_arr0_decay() {
        reg_c2_layer3_arr0_tg0_toupdate_value = hdr.decay_update.layer3_arr0_tg0_decay & LAYER3_DECAY_DATA;
        reg_c2_layer3_arr0_tg1_toupdate_value = hdr.decay_update.layer3_arr0_tg1_decay & LAYER3_DECAY_DATA;
    }

    table reg_c2_layer3_arr0_dyn_table {
        key = {
            reg_c_timer3_arr0_diff                                                  : exact;
            reg_c2_layer2_arr0_tg0_res[(LAYER2_BIT_SIZE*2)-1:(LAYER2_BIT_SIZE*2)-1] : exact;
            reg_c2_layer2_arr0_tg0_res[(LAYER2_BIT_SIZE*1)-1:(LAYER2_BIT_SIZE*1)-1] : exact;
            reg_c2_layer2_arr0_tg1_res[(LAYER2_BIT_SIZE*2)-1:(LAYER2_BIT_SIZE*2)-1] : exact;
            reg_c2_layer2_arr0_tg1_res[(LAYER2_BIT_SIZE*1)-1:(LAYER2_BIT_SIZE*1)-1] : exact;
            hdr.decay_update.isValid()                                              : exact;
        }
        actions = {
            reg_c2_layer3_arr0_merge;
            reg_c2_layer3_arr0_decay;
        }
    }

    action reg_c2_layer3_arr1_merge(bit<LAYER3_TOTAL_BIT_SIZE> slices0, bit<LAYER3_TOTAL_BIT_SIZE> slices1) {
        reg_c2_layer3_arr1_tg0_toupdate_value = slices0;
        reg_c2_layer3_arr1_tg1_toupdate_value = slices1;
    }

    action reg_c2_layer3_arr1_decay() {
        reg_c2_layer3_arr1_tg0_toupdate_value = hdr.decay_update.layer3_arr1_tg0_decay & LAYER3_DECAY_DATA;
        reg_c2_layer3_arr1_tg1_toupdate_value = hdr.decay_update.layer3_arr1_tg1_decay & LAYER3_DECAY_DATA;
    }

    table reg_c2_layer3_arr1_dyn_table {
        key = {
            reg_c_timer3_arr1_diff                                                  : exact;
            reg_c2_layer2_arr1_tg0_res[(LAYER2_BIT_SIZE*2)-1:(LAYER2_BIT_SIZE*2)-1] : exact;
            reg_c2_layer2_arr1_tg0_res[(LAYER2_BIT_SIZE*1)-1:(LAYER2_BIT_SIZE*1)-1] : exact;
            reg_c2_layer2_arr1_tg1_res[(LAYER2_BIT_SIZE*2)-1:(LAYER2_BIT_SIZE*2)-1] : exact;
            reg_c2_layer2_arr1_tg1_res[(LAYER2_BIT_SIZE*1)-1:(LAYER2_BIT_SIZE*1)-1] : exact;
            hdr.decay_update.isValid()                                              : exact;
        }
        actions = {
            reg_c2_layer3_arr1_merge;
            reg_c2_layer3_arr1_decay;
        }
    }

    action reg_c2_layer1_arr0_w1_plus_action() {
        reg_c2_layer1_arr0_cur_res = reg_c2_layer1_arr0_w1_plus.execute(reg_c2_key_a[LAYER1_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer1_arr0_w1_update_action() {
        reg_c2_layer1_arr0_cur_res = reg_c2_layer1_arr0_w1_update.execute(reg_c2_key_a[LAYER1_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer1_arr0_w1_setbit_action() {
        reg_c2_layer1_arr0_cur_res = reg_c2_layer1_arr0_w1_setbit.execute(reg_c2_key_a[LAYER1_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer1_arr0_w1_read_action() {
        reg_c2_layer1_arr0_res = reg_c2_layer1_arr0_w1_setbit.execute(reg_c2_key_a[LAYER1_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer1_arr0_w2_plus_action() {
        reg_c2_layer1_arr0_cur_res = reg_c2_layer1_arr0_w2_plus.execute(reg_c2_key_a[LAYER1_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer1_arr0_w2_update_action() {
        reg_c2_layer1_arr0_cur_res = reg_c2_layer1_arr0_w2_update.execute(reg_c2_key_a[LAYER1_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer1_arr0_w2_setbit_action() {
        reg_c2_layer1_arr0_cur_res = reg_c2_layer1_arr0_w2_setbit.execute(reg_c2_key_a[LAYER1_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer1_arr0_w2_read_action() {
        reg_c2_layer1_arr0_res = reg_c2_layer1_arr0_w2_setbit.execute(reg_c2_key_a[LAYER1_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer1_arr1_w1_plus_action() {
        reg_c2_layer1_arr1_cur_res = reg_c2_layer1_arr1_w1_plus.execute(reg_c2_key_b[LAYER1_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer1_arr1_w1_update_action() {
        reg_c2_layer1_arr1_cur_res = reg_c2_layer1_arr1_w1_update.execute(reg_c2_key_b[LAYER1_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer1_arr1_w1_setbit_action() {
        reg_c2_layer1_arr1_cur_res = reg_c2_layer1_arr1_w1_setbit.execute(reg_c2_key_b[LAYER1_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer1_arr1_w1_read_action() {
        reg_c2_layer1_arr1_res = reg_c2_layer1_arr1_w1_setbit.execute(reg_c2_key_b[LAYER1_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer1_arr1_w2_plus_action() {
        reg_c2_layer1_arr1_cur_res = reg_c2_layer1_arr1_w2_plus.execute(reg_c2_key_b[LAYER1_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer1_arr1_w2_update_action() {
        reg_c2_layer1_arr1_cur_res = reg_c2_layer1_arr1_w2_update.execute(reg_c2_key_b[LAYER1_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer1_arr1_w2_setbit_action() {
        reg_c2_layer1_arr1_cur_res = reg_c2_layer1_arr1_w2_setbit.execute(reg_c2_key_b[LAYER1_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer1_arr1_w2_read_action() {
        reg_c2_layer1_arr1_res = reg_c2_layer1_arr1_w2_setbit.execute(reg_c2_key_b[LAYER1_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer2_arr0_tg0_plus_action() {
        reg_c2_layer2_arr0_tg0_res = reg_c2_layer2_arr0_tg0_plus.execute(reg_c2_key_a[LAYER2_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer2_arr0_tg0_decay_action() {
        reg_c2_layer2_arr0_tg0_res = reg_c2_layer2_arr0_tg0_decay.execute(reg_c2_key_a[LAYER2_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer2_arr0_tg0_setbit_action() {
        reg_c2_layer2_arr0_tg0_res = reg_c2_layer2_arr0_tg0_setbit.execute(reg_c2_key_a[LAYER2_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer2_arr0_tg0_read_action() {
        reg_c2_layer2_arr0_tg0_res = reg_c2_layer2_arr0_tg0_read.execute(reg_c2_key_a[LAYER2_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer2_arr1_tg0_plus_action() {
        reg_c2_layer2_arr1_tg0_res = reg_c2_layer2_arr1_tg0_plus.execute(reg_c2_key_b[LAYER2_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer2_arr1_tg0_decay_action() {
        reg_c2_layer2_arr1_tg0_res = reg_c2_layer2_arr1_tg0_decay.execute(reg_c2_key_b[LAYER2_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer2_arr1_tg0_setbit_action() {
        reg_c2_layer2_arr1_tg0_res = reg_c2_layer2_arr1_tg0_setbit.execute(reg_c2_key_b[LAYER2_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer2_arr1_tg0_read_action() {
        reg_c2_layer2_arr1_tg0_res = reg_c2_layer2_arr1_tg0_read.execute(reg_c2_key_b[LAYER2_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer2_arr0_tg1_plus_action() {
        reg_c2_layer2_arr0_tg1_res = reg_c2_layer2_arr0_tg1_plus.execute(reg_c2_key_a[LAYER2_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer2_arr0_tg1_decay_action() {
        reg_c2_layer2_arr0_tg1_res = reg_c2_layer2_arr0_tg1_decay.execute(reg_c2_key_a[LAYER2_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer2_arr0_tg1_setbit_action() {
        reg_c2_layer2_arr0_tg1_res = reg_c2_layer2_arr0_tg1_setbit.execute(reg_c2_key_a[LAYER2_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer2_arr0_tg1_read_action() {
        reg_c2_layer2_arr0_tg1_res = reg_c2_layer2_arr0_tg1_read.execute(reg_c2_key_a[LAYER2_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer2_arr1_tg1_plus_action() {
        reg_c2_layer2_arr1_tg1_res = reg_c2_layer2_arr1_tg1_plus.execute(reg_c2_key_b[LAYER2_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer2_arr1_tg1_decay_action() {
        reg_c2_layer2_arr1_tg1_res = reg_c2_layer2_arr1_tg1_decay.execute(reg_c2_key_b[LAYER2_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer2_arr1_tg1_setbit_action() {
        reg_c2_layer2_arr1_tg1_res = reg_c2_layer2_arr1_tg1_setbit.execute(reg_c2_key_b[LAYER2_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer2_arr1_tg1_read_action() {
        reg_c2_layer2_arr1_tg1_res = reg_c2_layer2_arr1_tg1_read.execute(reg_c2_key_b[LAYER2_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer3_arr0_tg0_plus_action() {
        reg_c2_layer3_arr0_tg0_res = reg_c2_layer3_arr0_tg0_plus.execute(reg_c2_key_a[LAYER3_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer3_arr0_tg0_decay_action() {
        reg_c2_layer3_arr0_tg0_res = reg_c2_layer3_arr0_tg0_decay.execute(reg_c2_key_a[LAYER3_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer3_arr0_tg0_setbit_action() {
        reg_c2_layer3_arr0_tg0_res = reg_c2_layer3_arr0_tg0_setbit.execute(reg_c2_key_a[LAYER3_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer3_arr0_tg0_read_action() {
        reg_c2_layer3_arr0_tg0_res = reg_c2_layer3_arr0_tg0_read.execute(reg_c2_key_a[LAYER3_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer3_arr1_tg0_plus_action() {
        reg_c2_layer3_arr1_tg0_res = reg_c2_layer3_arr1_tg0_plus.execute(reg_c2_key_b[LAYER3_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer3_arr1_tg0_decay_action() {
        reg_c2_layer3_arr1_tg0_res = reg_c2_layer3_arr1_tg0_decay.execute(reg_c2_key_b[LAYER3_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer3_arr1_tg0_setbit_action() {
        reg_c2_layer3_arr1_tg0_res = reg_c2_layer3_arr1_tg0_setbit.execute(reg_c2_key_b[LAYER3_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer3_arr1_tg0_read_action() {
        reg_c2_layer3_arr1_tg0_res = reg_c2_layer3_arr1_tg0_read.execute(reg_c2_key_b[LAYER3_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer3_arr0_tg1_plus_action() {
        reg_c2_layer3_arr0_tg1_res = reg_c2_layer3_arr0_tg1_plus.execute(reg_c2_key_a[LAYER3_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer3_arr0_tg1_decay_action() {
        reg_c2_layer3_arr0_tg1_res = reg_c2_layer3_arr0_tg1_decay.execute(reg_c2_key_a[LAYER3_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer3_arr0_tg1_setbit_action() {
        reg_c2_layer3_arr0_tg1_res = reg_c2_layer3_arr0_tg1_setbit.execute(reg_c2_key_a[LAYER3_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer3_arr0_tg1_read_action() {
        reg_c2_layer3_arr0_tg1_res = reg_c2_layer3_arr0_tg1_read.execute(reg_c2_key_a[LAYER3_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer3_arr1_tg1_plus_action() {
        reg_c2_layer3_arr1_tg1_res = reg_c2_layer3_arr1_tg1_plus.execute(reg_c2_key_b[LAYER3_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer3_arr1_tg1_decay_action() {
        reg_c2_layer3_arr1_tg1_res = reg_c2_layer3_arr1_tg1_decay.execute(reg_c2_key_b[LAYER3_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer3_arr1_tg1_setbit_action() {
        reg_c2_layer3_arr1_tg1_res = reg_c2_layer3_arr1_tg1_setbit.execute(reg_c2_key_b[LAYER3_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer3_arr1_tg1_read_action() {
        reg_c2_layer3_arr1_tg1_res = reg_c2_layer3_arr1_tg1_read.execute(reg_c2_key_b[LAYER3_ENTRY_SIZE_EXP-1:0]);
    }

    table reg_c2_layer1_arr0_w1_table {
        key = {
            global_time1                : exact;
            reg_c_timer1_arr0_res       : exact;
            hdr.overflow.isValid()      : exact;
            hdr.decay_update.isValid()  : exact;
        }
        actions = {
            reg_c2_layer1_arr0_w1_plus_action;
            reg_c2_layer1_arr0_w1_update_action;
            reg_c2_layer1_arr0_w1_setbit_action;
        }
    }

    table reg_c2_layer1_arr0_w2_table {
        key = {
            global_time1                : exact;
            reg_c_timer1_arr0_res       : exact;
            hdr.overflow.isValid()      : exact;
            hdr.decay_update.isValid()  : exact;
        }
        actions = {
            reg_c2_layer1_arr0_w2_plus_action;
            reg_c2_layer1_arr0_w2_update_action;
            reg_c2_layer1_arr0_w2_setbit_action;
        }
    }

    table reg_c2_layer1_arr1_w1_table {
        key = {
            global_time1                : exact;
            reg_c_timer1_arr1_res       : exact;
            hdr.overflow.isValid()      : exact;
            hdr.decay_update.isValid()  : exact;
        }
        actions = {
            reg_c2_layer1_arr1_w1_plus_action;
            reg_c2_layer1_arr1_w1_update_action;
            reg_c2_layer1_arr1_w1_setbit_action;
        }
    }

    table reg_c2_layer1_arr1_w2_table {
        key = {
            global_time1                : exact;
            reg_c_timer1_arr1_res       : exact;
            hdr.overflow.isValid()      : exact;
            hdr.decay_update.isValid()  : exact;
        }
        actions = {
            reg_c2_layer1_arr1_w2_plus_action;
            reg_c2_layer1_arr1_w2_update_action;
            reg_c2_layer1_arr1_w2_setbit_action;
        }
    }

    table reg_c2_layer2_arr0_tg0_table {
        key = {
            hdr.overflow.isValid()                  : exact;
            hdr.decay_update.isValid()              : exact;
            hdr.decay_update.layer2_arr0_is_decay   : exact;
        }
        actions = {
            reg_c2_layer2_arr0_tg0_plus_action;
            reg_c2_layer2_arr0_tg0_decay_action;
            reg_c2_layer2_arr0_tg0_setbit_action;
            reg_c2_layer2_arr0_tg0_read_action;
        }
    }

    table reg_c2_layer2_arr0_tg1_table {
        key = {
            hdr.overflow.isValid()                  : exact;
            hdr.decay_update.isValid()              : exact;
            hdr.decay_update.layer2_arr0_is_decay   : exact;
        }
        actions = {
            reg_c2_layer2_arr0_tg1_plus_action;
            reg_c2_layer2_arr0_tg1_decay_action;
            reg_c2_layer2_arr0_tg1_setbit_action;
            reg_c2_layer2_arr0_tg1_read_action;
        }
    }

    table reg_c2_layer2_arr1_tg0_table {
        key = {
            hdr.overflow.isValid()                  : exact;
            hdr.decay_update.isValid()              : exact;
            hdr.decay_update.layer2_arr1_is_decay   : exact;
        }
        actions = {
            reg_c2_layer2_arr1_tg0_plus_action;
            reg_c2_layer2_arr1_tg0_decay_action;
            reg_c2_layer2_arr1_tg0_setbit_action;
            reg_c2_layer2_arr1_tg0_read_action;
        }
    }

    table reg_c2_layer2_arr1_tg1_table {
        key = {
            hdr.overflow.isValid()                  : exact;
            hdr.decay_update.isValid()              : exact;
            hdr.decay_update.layer2_arr1_is_decay   : exact;
        }
        actions = {
            reg_c2_layer2_arr1_tg1_plus_action;
            reg_c2_layer2_arr1_tg1_decay_action;
            reg_c2_layer2_arr1_tg1_setbit_action;
            reg_c2_layer2_arr1_tg1_read_action;
        }
    }

    table reg_c2_layer3_arr0_tg0_table {
        key = {
            hdr.overflow.isValid()                  : exact;
            hdr.decay_update.isValid()              : exact;
            hdr.decay_update.layer3_arr0_is_decay   : exact;
        }
        actions = {
            reg_c2_layer3_arr0_tg0_plus_action;
            reg_c2_layer3_arr0_tg0_decay_action;
            reg_c2_layer3_arr0_tg0_setbit_action;
            reg_c2_layer3_arr0_tg0_read_action;
        }
    }

    table reg_c2_layer3_arr0_tg1_table {
        key = {
            hdr.overflow.isValid()                  : exact;
            hdr.decay_update.isValid()              : exact;
            hdr.decay_update.layer3_arr0_is_decay   : exact;
        }
        actions = {
            reg_c2_layer3_arr0_tg1_plus_action;
            reg_c2_layer3_arr0_tg1_decay_action;
            reg_c2_layer3_arr0_tg1_setbit_action;
            reg_c2_layer3_arr0_tg1_read_action;
        }
    }

    table reg_c2_layer3_arr1_tg0_table {
        key = {
            hdr.overflow.isValid()                  : exact;
            hdr.decay_update.isValid()              : exact;
            hdr.decay_update.layer3_arr1_is_decay   : exact;
        }
        actions = {
            reg_c2_layer3_arr1_tg0_plus_action;
            reg_c2_layer3_arr1_tg0_decay_action;
            reg_c2_layer3_arr1_tg0_setbit_action;
            reg_c2_layer3_arr1_tg0_read_action;
        }
    }

    table reg_c2_layer3_arr1_tg1_table {
        key = {
            hdr.overflow.isValid()                  : exact;
            hdr.decay_update.isValid()              : exact;
            hdr.decay_update.layer3_arr1_is_decay   : exact;
        }
        actions = {
            reg_c2_layer3_arr1_tg1_plus_action;
            reg_c2_layer3_arr1_tg1_decay_action;
            reg_c2_layer3_arr1_tg1_setbit_action;
            reg_c2_layer3_arr1_tg1_read_action;
        }
    }

    action extract_reg_c2_layer1() {
        md.extracted_reg_c2_arr0_slice0[LAYER1_BIT_SIZE-2:0] = reg_c2_layer1_arr0_cur_res[(LAYER1_BIT_SIZE*4)-2:(LAYER1_BIT_SIZE*3)];
        md.extracted_reg_c2_arr0_slice1[LAYER1_BIT_SIZE-2:0] = reg_c2_layer1_arr0_cur_res[(LAYER1_BIT_SIZE*3)-2:(LAYER1_BIT_SIZE*2)];
        md.extracted_reg_c2_arr0_slice2[LAYER1_BIT_SIZE-2:0] = reg_c2_layer1_arr0_cur_res[(LAYER1_BIT_SIZE*2)-2:(LAYER1_BIT_SIZE*1)];
        md.extracted_reg_c2_arr0_slice3[LAYER1_BIT_SIZE-2:0] = reg_c2_layer1_arr0_cur_res[(LAYER1_BIT_SIZE*1)-2:(LAYER1_BIT_SIZE*0)];

        md.extracted_reg_c2_arr1_slice0[LAYER1_BIT_SIZE-2:0] = reg_c2_layer1_arr1_cur_res[(LAYER1_BIT_SIZE*4)-2:(LAYER1_BIT_SIZE*3)];
        md.extracted_reg_c2_arr1_slice1[LAYER1_BIT_SIZE-2:0] = reg_c2_layer1_arr1_cur_res[(LAYER1_BIT_SIZE*3)-2:(LAYER1_BIT_SIZE*2)];
        md.extracted_reg_c2_arr1_slice2[LAYER1_BIT_SIZE-2:0] = reg_c2_layer1_arr1_cur_res[(LAYER1_BIT_SIZE*2)-2:(LAYER1_BIT_SIZE*1)];
        md.extracted_reg_c2_arr1_slice3[LAYER1_BIT_SIZE-2:0] = reg_c2_layer1_arr1_cur_res[(LAYER1_BIT_SIZE*1)-2:(LAYER1_BIT_SIZE*0)];
    }

    action extract_reg_c2_layer2_arr0_0000() {
        md.extracted_reg_c2_arr0_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr0_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr0_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr0_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
    }

    action extract_reg_c2_layer2_arr0_0001() {
        md.extracted_reg_c2_arr0_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr0_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr0_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr0_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr0_tg1_res[(LAYER2_BIT_SIZE*1)-2:(LAYER2_BIT_SIZE*0)];
    }

    action extract_reg_c2_layer2_arr0_0010() {
        md.extracted_reg_c2_arr0_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr0_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr0_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr0_tg1_res[(LAYER2_BIT_SIZE*2)-2:(LAYER2_BIT_SIZE*1)];
        md.extracted_reg_c2_arr0_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
    }

    action extract_reg_c2_layer2_arr0_0011() {
        md.extracted_reg_c2_arr0_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr0_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr0_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr0_tg1_res[(LAYER2_BIT_SIZE*2)-2:(LAYER2_BIT_SIZE*1)];
        md.extracted_reg_c2_arr0_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr0_tg1_res[(LAYER2_BIT_SIZE*1)-2:(LAYER2_BIT_SIZE*0)];
    }

    action extract_reg_c2_layer2_arr0_0100() {
        md.extracted_reg_c2_arr0_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr0_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr0_tg0_res[(LAYER2_BIT_SIZE*1)-2:(LAYER2_BIT_SIZE*0)];
        md.extracted_reg_c2_arr0_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr0_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
    }

    action extract_reg_c2_layer2_arr0_0101() {
        md.extracted_reg_c2_arr0_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr0_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr0_tg0_res[(LAYER2_BIT_SIZE*1)-2:(LAYER2_BIT_SIZE*0)];
        md.extracted_reg_c2_arr0_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr0_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr0_tg1_res[(LAYER2_BIT_SIZE*1)-2:(LAYER2_BIT_SIZE*0)];
    }

    action extract_reg_c2_layer2_arr0_0110() {
        md.extracted_reg_c2_arr0_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr0_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr0_tg0_res[(LAYER2_BIT_SIZE*1)-2:(LAYER2_BIT_SIZE*0)];
        md.extracted_reg_c2_arr0_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr0_tg1_res[(LAYER2_BIT_SIZE*2)-2:(LAYER2_BIT_SIZE*1)];
        md.extracted_reg_c2_arr0_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
    }

    action extract_reg_c2_layer2_arr0_0111() {
        md.extracted_reg_c2_arr0_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr0_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr0_tg0_res[(LAYER2_BIT_SIZE*1)-2:(LAYER2_BIT_SIZE*0)];
        md.extracted_reg_c2_arr0_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr0_tg1_res[(LAYER2_BIT_SIZE*2)-2:(LAYER2_BIT_SIZE*1)];
        md.extracted_reg_c2_arr0_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr0_tg1_res[(LAYER2_BIT_SIZE*1)-2:(LAYER2_BIT_SIZE*0)];
    }

    action extract_reg_c2_layer2_arr0_1000() {
        md.extracted_reg_c2_arr0_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr0_tg0_res[(LAYER2_BIT_SIZE*2)-2:(LAYER2_BIT_SIZE*1)];
        md.extracted_reg_c2_arr0_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr0_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr0_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
    }

    action extract_reg_c2_layer2_arr0_1001() {
        md.extracted_reg_c2_arr0_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr0_tg0_res[(LAYER2_BIT_SIZE*2)-2:(LAYER2_BIT_SIZE*1)];
        md.extracted_reg_c2_arr0_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr0_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr0_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr0_tg1_res[(LAYER2_BIT_SIZE*1)-2:(LAYER2_BIT_SIZE*0)];
    }

    action extract_reg_c2_layer2_arr0_1010() {
        md.extracted_reg_c2_arr0_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr0_tg0_res[(LAYER2_BIT_SIZE*2)-2:(LAYER2_BIT_SIZE*1)];
        md.extracted_reg_c2_arr0_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr0_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr0_tg1_res[(LAYER2_BIT_SIZE*2)-2:(LAYER2_BIT_SIZE*1)];
        md.extracted_reg_c2_arr0_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
    }

    action extract_reg_c2_layer2_arr0_1011() {
        md.extracted_reg_c2_arr0_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr0_tg0_res[(LAYER2_BIT_SIZE*2)-2:(LAYER2_BIT_SIZE*1)];
        md.extracted_reg_c2_arr0_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr0_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr0_tg1_res[(LAYER2_BIT_SIZE*2)-2:(LAYER2_BIT_SIZE*1)];
        md.extracted_reg_c2_arr0_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr0_tg1_res[(LAYER2_BIT_SIZE*1)-2:(LAYER2_BIT_SIZE*0)];
    }

    action extract_reg_c2_layer2_arr0_1100() {
        md.extracted_reg_c2_arr0_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr0_tg0_res[(LAYER2_BIT_SIZE*2)-2:(LAYER2_BIT_SIZE*1)];
        md.extracted_reg_c2_arr0_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr0_tg0_res[(LAYER2_BIT_SIZE*1)-2:(LAYER2_BIT_SIZE*0)];
        md.extracted_reg_c2_arr0_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr0_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
    }

    action extract_reg_c2_layer2_arr0_1101() {
        md.extracted_reg_c2_arr0_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr0_tg0_res[(LAYER2_BIT_SIZE*2)-2:(LAYER2_BIT_SIZE*1)];
        md.extracted_reg_c2_arr0_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr0_tg0_res[(LAYER2_BIT_SIZE*1)-2:(LAYER2_BIT_SIZE*0)];
        md.extracted_reg_c2_arr0_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr0_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr0_tg1_res[(LAYER2_BIT_SIZE*1)-2:(LAYER2_BIT_SIZE*0)];
    }

    action extract_reg_c2_layer2_arr0_1110() {
        md.extracted_reg_c2_arr0_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr0_tg0_res[(LAYER2_BIT_SIZE*2)-2:(LAYER2_BIT_SIZE*1)];
        md.extracted_reg_c2_arr0_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr0_tg0_res[(LAYER2_BIT_SIZE*1)-2:(LAYER2_BIT_SIZE*0)];
        md.extracted_reg_c2_arr0_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr0_tg1_res[(LAYER2_BIT_SIZE*2)-2:(LAYER2_BIT_SIZE*1)];
        md.extracted_reg_c2_arr0_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
    }

    action extract_reg_c2_layer2_arr0_1111() {
        md.extracted_reg_c2_arr0_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr0_tg0_res[(LAYER2_BIT_SIZE*2)-2:(LAYER2_BIT_SIZE*1)];
        md.extracted_reg_c2_arr0_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr0_tg0_res[(LAYER2_BIT_SIZE*1)-2:(LAYER2_BIT_SIZE*0)];
        md.extracted_reg_c2_arr0_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr0_tg1_res[(LAYER2_BIT_SIZE*2)-2:(LAYER2_BIT_SIZE*1)];
        md.extracted_reg_c2_arr0_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr0_tg1_res[(LAYER2_BIT_SIZE*1)-2:(LAYER2_BIT_SIZE*0)];
    }

    action extract_reg_c2_layer2_arr1_0000() {
        md.extracted_reg_c2_arr1_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr1_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr1_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr1_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
    }

    action extract_reg_c2_layer2_arr1_0001() {
        md.extracted_reg_c2_arr1_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr1_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr1_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr1_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr1_tg1_res[(LAYER2_BIT_SIZE*1)-2:(LAYER2_BIT_SIZE*0)];
    }

    action extract_reg_c2_layer2_arr1_0010() {
        md.extracted_reg_c2_arr1_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr1_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr1_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr1_tg1_res[(LAYER2_BIT_SIZE*2)-2:(LAYER2_BIT_SIZE*1)];
        md.extracted_reg_c2_arr1_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
    }

    action extract_reg_c2_layer2_arr1_0011() {
        md.extracted_reg_c2_arr1_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr1_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr1_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr1_tg1_res[(LAYER2_BIT_SIZE*2)-2:(LAYER2_BIT_SIZE*1)];
        md.extracted_reg_c2_arr1_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr1_tg1_res[(LAYER2_BIT_SIZE*1)-2:(LAYER2_BIT_SIZE*0)];
    }

    action extract_reg_c2_layer2_arr1_0100() {
        md.extracted_reg_c2_arr1_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr1_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr1_tg0_res[(LAYER2_BIT_SIZE*1)-2:(LAYER2_BIT_SIZE*0)];
        md.extracted_reg_c2_arr1_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr1_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
    }

    action extract_reg_c2_layer2_arr1_0101() {
        md.extracted_reg_c2_arr1_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr1_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr1_tg0_res[(LAYER2_BIT_SIZE*1)-2:(LAYER2_BIT_SIZE*0)];
        md.extracted_reg_c2_arr1_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr1_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr1_tg1_res[(LAYER2_BIT_SIZE*1)-2:(LAYER2_BIT_SIZE*0)];
    }

    action extract_reg_c2_layer2_arr1_0110() {
        md.extracted_reg_c2_arr1_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr1_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr1_tg0_res[(LAYER2_BIT_SIZE*1)-2:(LAYER2_BIT_SIZE*0)];
        md.extracted_reg_c2_arr1_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr1_tg1_res[(LAYER2_BIT_SIZE*2)-2:(LAYER2_BIT_SIZE*1)];
        md.extracted_reg_c2_arr1_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
    }

    action extract_reg_c2_layer2_arr1_0111() {
        md.extracted_reg_c2_arr1_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr1_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr1_tg0_res[(LAYER2_BIT_SIZE*1)-2:(LAYER2_BIT_SIZE*0)];
        md.extracted_reg_c2_arr1_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr1_tg1_res[(LAYER2_BIT_SIZE*2)-2:(LAYER2_BIT_SIZE*1)];
        md.extracted_reg_c2_arr1_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr1_tg1_res[(LAYER2_BIT_SIZE*1)-2:(LAYER2_BIT_SIZE*0)];
    }

    action extract_reg_c2_layer2_arr1_1000() {
        md.extracted_reg_c2_arr1_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr1_tg0_res[(LAYER2_BIT_SIZE*2)-2:(LAYER2_BIT_SIZE*1)];
        md.extracted_reg_c2_arr1_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr1_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr1_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
    }

    action extract_reg_c2_layer2_arr1_1001() {
        md.extracted_reg_c2_arr1_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr1_tg0_res[(LAYER2_BIT_SIZE*2)-2:(LAYER2_BIT_SIZE*1)];
        md.extracted_reg_c2_arr1_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr1_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr1_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr1_tg1_res[(LAYER2_BIT_SIZE*1)-2:(LAYER2_BIT_SIZE*0)];
    }

    action extract_reg_c2_layer2_arr1_1010() {
        md.extracted_reg_c2_arr1_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr1_tg0_res[(LAYER2_BIT_SIZE*2)-2:(LAYER2_BIT_SIZE*1)];
        md.extracted_reg_c2_arr1_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr1_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr1_tg1_res[(LAYER2_BIT_SIZE*2)-2:(LAYER2_BIT_SIZE*1)];
        md.extracted_reg_c2_arr1_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
    }

    action extract_reg_c2_layer2_arr1_1011() {
        md.extracted_reg_c2_arr1_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr1_tg0_res[(LAYER2_BIT_SIZE*2)-2:(LAYER2_BIT_SIZE*1)];
        md.extracted_reg_c2_arr1_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr1_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr1_tg1_res[(LAYER2_BIT_SIZE*2)-2:(LAYER2_BIT_SIZE*1)];
        md.extracted_reg_c2_arr1_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr1_tg1_res[(LAYER2_BIT_SIZE*1)-2:(LAYER2_BIT_SIZE*0)];
    }

    action extract_reg_c2_layer2_arr1_1100() {
        md.extracted_reg_c2_arr1_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr1_tg0_res[(LAYER2_BIT_SIZE*2)-2:(LAYER2_BIT_SIZE*1)];
        md.extracted_reg_c2_arr1_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr1_tg0_res[(LAYER2_BIT_SIZE*1)-2:(LAYER2_BIT_SIZE*0)];
        md.extracted_reg_c2_arr1_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr1_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
    }

    action extract_reg_c2_layer2_arr1_1101() {
        md.extracted_reg_c2_arr1_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr1_tg0_res[(LAYER2_BIT_SIZE*2)-2:(LAYER2_BIT_SIZE*1)];
        md.extracted_reg_c2_arr1_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr1_tg0_res[(LAYER2_BIT_SIZE*1)-2:(LAYER2_BIT_SIZE*0)];
        md.extracted_reg_c2_arr1_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
        md.extracted_reg_c2_arr1_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr1_tg1_res[(LAYER2_BIT_SIZE*1)-2:(LAYER2_BIT_SIZE*0)];
    }

    action extract_reg_c2_layer2_arr1_1110() {
        md.extracted_reg_c2_arr1_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr1_tg0_res[(LAYER2_BIT_SIZE*2)-2:(LAYER2_BIT_SIZE*1)];
        md.extracted_reg_c2_arr1_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr1_tg0_res[(LAYER2_BIT_SIZE*1)-2:(LAYER2_BIT_SIZE*0)];
        md.extracted_reg_c2_arr1_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr1_tg1_res[(LAYER2_BIT_SIZE*2)-2:(LAYER2_BIT_SIZE*1)];
        md.extracted_reg_c2_arr1_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = 0;
    }

    action extract_reg_c2_layer2_arr1_1111() {
        md.extracted_reg_c2_arr1_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr1_tg0_res[(LAYER2_BIT_SIZE*2)-2:(LAYER2_BIT_SIZE*1)];
        md.extracted_reg_c2_arr1_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr1_tg0_res[(LAYER2_BIT_SIZE*1)-2:(LAYER2_BIT_SIZE*0)];
        md.extracted_reg_c2_arr1_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr1_tg1_res[(LAYER2_BIT_SIZE*2)-2:(LAYER2_BIT_SIZE*1)];
        md.extracted_reg_c2_arr1_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-3:LAYER1_BIT_SIZE-1] = reg_c2_layer2_arr1_tg1_res[(LAYER2_BIT_SIZE*1)-2:(LAYER2_BIT_SIZE*0)];
    }

    action extract_reg_c2_layer3_arr0_0000() {
        md.extracted_reg_c2_arr0_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr0_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr0_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr0_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
    }

    action extract_reg_c2_layer3_arr0_0001() {
        md.extracted_reg_c2_arr0_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr0_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr0_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr0_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr0_tg1_res[(LAYER3_BIT_SIZE*1)-2:(LAYER3_BIT_SIZE*0)];
    }

    action extract_reg_c2_layer3_arr0_0010() {
        md.extracted_reg_c2_arr0_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr0_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr0_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr0_tg1_res[(LAYER3_BIT_SIZE*2)-2:(LAYER3_BIT_SIZE*1)];
        md.extracted_reg_c2_arr0_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
    }

    action extract_reg_c2_layer3_arr0_0011() {
        md.extracted_reg_c2_arr0_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr0_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr0_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr0_tg1_res[(LAYER3_BIT_SIZE*2)-2:(LAYER3_BIT_SIZE*1)];
        md.extracted_reg_c2_arr0_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr0_tg1_res[(LAYER3_BIT_SIZE*1)-2:(LAYER3_BIT_SIZE*0)];
    }

    action extract_reg_c2_layer3_arr0_0100() {
        md.extracted_reg_c2_arr0_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr0_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr0_tg0_res[(LAYER3_BIT_SIZE*1)-2:(LAYER3_BIT_SIZE*0)];
        md.extracted_reg_c2_arr0_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr0_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
    }

    action extract_reg_c2_layer3_arr0_0101() {
        md.extracted_reg_c2_arr0_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr0_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr0_tg0_res[(LAYER3_BIT_SIZE*1)-2:(LAYER3_BIT_SIZE*0)];
        md.extracted_reg_c2_arr0_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr0_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr0_tg1_res[(LAYER3_BIT_SIZE*1)-2:(LAYER3_BIT_SIZE*0)];
    }

    action extract_reg_c2_layer3_arr0_0110() {
        md.extracted_reg_c2_arr0_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr0_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr0_tg0_res[(LAYER3_BIT_SIZE*1)-2:(LAYER3_BIT_SIZE*0)];
        md.extracted_reg_c2_arr0_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr0_tg1_res[(LAYER3_BIT_SIZE*2)-2:(LAYER3_BIT_SIZE*1)];
        md.extracted_reg_c2_arr0_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
    }

    action extract_reg_c2_layer3_arr0_0111() {
        md.extracted_reg_c2_arr0_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr0_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr0_tg0_res[(LAYER3_BIT_SIZE*1)-2:(LAYER3_BIT_SIZE*0)];
        md.extracted_reg_c2_arr0_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr0_tg1_res[(LAYER3_BIT_SIZE*2)-2:(LAYER3_BIT_SIZE*1)];
        md.extracted_reg_c2_arr0_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr0_tg1_res[(LAYER3_BIT_SIZE*1)-2:(LAYER3_BIT_SIZE*0)];
    }

    action extract_reg_c2_layer3_arr0_1000() {
        md.extracted_reg_c2_arr0_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr0_tg0_res[(LAYER3_BIT_SIZE*2)-2:(LAYER3_BIT_SIZE*1)];
        md.extracted_reg_c2_arr0_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr0_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr0_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
    }

    action extract_reg_c2_layer3_arr0_1001() {
        md.extracted_reg_c2_arr0_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr0_tg0_res[(LAYER3_BIT_SIZE*2)-2:(LAYER3_BIT_SIZE*1)];
        md.extracted_reg_c2_arr0_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr0_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr0_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr0_tg1_res[(LAYER3_BIT_SIZE*1)-2:(LAYER3_BIT_SIZE*0)];
    }

    action extract_reg_c2_layer3_arr0_1010() {
        md.extracted_reg_c2_arr0_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr0_tg0_res[(LAYER3_BIT_SIZE*2)-2:(LAYER3_BIT_SIZE*1)];
        md.extracted_reg_c2_arr0_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr0_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr0_tg1_res[(LAYER3_BIT_SIZE*2)-2:(LAYER3_BIT_SIZE*1)];
        md.extracted_reg_c2_arr0_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
    }

    action extract_reg_c2_layer3_arr0_1011() {
        md.extracted_reg_c2_arr0_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr0_tg0_res[(LAYER3_BIT_SIZE*2)-2:(LAYER3_BIT_SIZE*1)];
        md.extracted_reg_c2_arr0_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr0_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr0_tg1_res[(LAYER3_BIT_SIZE*2)-2:(LAYER3_BIT_SIZE*1)];
        md.extracted_reg_c2_arr0_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr0_tg1_res[(LAYER3_BIT_SIZE*1)-2:(LAYER3_BIT_SIZE*0)];
    }

    action extract_reg_c2_layer3_arr0_1100() {
        md.extracted_reg_c2_arr0_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr0_tg0_res[(LAYER3_BIT_SIZE*2)-2:(LAYER3_BIT_SIZE*1)];
        md.extracted_reg_c2_arr0_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr0_tg0_res[(LAYER3_BIT_SIZE*1)-2:(LAYER3_BIT_SIZE*0)];
        md.extracted_reg_c2_arr0_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr0_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
    }

    action extract_reg_c2_layer3_arr0_1101() {
        md.extracted_reg_c2_arr0_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr0_tg0_res[(LAYER3_BIT_SIZE*2)-2:(LAYER3_BIT_SIZE*1)];
        md.extracted_reg_c2_arr0_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr0_tg0_res[(LAYER3_BIT_SIZE*1)-2:(LAYER3_BIT_SIZE*0)];
        md.extracted_reg_c2_arr0_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr0_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr0_tg1_res[(LAYER3_BIT_SIZE*1)-2:(LAYER3_BIT_SIZE*0)];
    }

    action extract_reg_c2_layer3_arr0_1110() {
        md.extracted_reg_c2_arr0_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr0_tg0_res[(LAYER3_BIT_SIZE*2)-2:(LAYER3_BIT_SIZE*1)];
        md.extracted_reg_c2_arr0_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr0_tg0_res[(LAYER3_BIT_SIZE*1)-2:(LAYER3_BIT_SIZE*0)];
        md.extracted_reg_c2_arr0_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr0_tg1_res[(LAYER3_BIT_SIZE*2)-2:(LAYER3_BIT_SIZE*1)];
        md.extracted_reg_c2_arr0_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
    }

    action extract_reg_c2_layer3_arr0_1111() {
        md.extracted_reg_c2_arr0_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr0_tg0_res[(LAYER3_BIT_SIZE*2)-2:(LAYER3_BIT_SIZE*1)];
        md.extracted_reg_c2_arr0_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr0_tg0_res[(LAYER3_BIT_SIZE*1)-2:(LAYER3_BIT_SIZE*0)];
        md.extracted_reg_c2_arr0_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr0_tg1_res[(LAYER3_BIT_SIZE*2)-2:(LAYER3_BIT_SIZE*1)];
        md.extracted_reg_c2_arr0_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr0_tg1_res[(LAYER3_BIT_SIZE*1)-2:(LAYER3_BIT_SIZE*0)];
    }

    action extract_reg_c2_layer3_arr1_0000() {
        md.extracted_reg_c2_arr1_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr1_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr1_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr1_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
    }

    action extract_reg_c2_layer3_arr1_0001() {
        md.extracted_reg_c2_arr1_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr1_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr1_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr1_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr1_tg1_res[(LAYER3_BIT_SIZE*1)-2:(LAYER3_BIT_SIZE*0)];
    }

    action extract_reg_c2_layer3_arr1_0010() {
        md.extracted_reg_c2_arr1_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr1_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr1_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr1_tg1_res[(LAYER3_BIT_SIZE*2)-2:(LAYER3_BIT_SIZE*1)];
        md.extracted_reg_c2_arr1_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
    }

    action extract_reg_c2_layer3_arr1_0011() {
        md.extracted_reg_c2_arr1_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr1_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr1_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr1_tg1_res[(LAYER3_BIT_SIZE*2)-2:(LAYER3_BIT_SIZE*1)];
        md.extracted_reg_c2_arr1_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr1_tg1_res[(LAYER3_BIT_SIZE*1)-2:(LAYER3_BIT_SIZE*0)];
    }

    action extract_reg_c2_layer3_arr1_0100() {
        md.extracted_reg_c2_arr1_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr1_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr1_tg0_res[(LAYER3_BIT_SIZE*1)-2:(LAYER3_BIT_SIZE*0)];
        md.extracted_reg_c2_arr1_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr1_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
    }

    action extract_reg_c2_layer3_arr1_0101() {
        md.extracted_reg_c2_arr1_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr1_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr1_tg0_res[(LAYER3_BIT_SIZE*1)-2:(LAYER3_BIT_SIZE*0)];
        md.extracted_reg_c2_arr1_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr1_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr1_tg1_res[(LAYER3_BIT_SIZE*1)-2:(LAYER3_BIT_SIZE*0)];
    }

    action extract_reg_c2_layer3_arr1_0110() {
        md.extracted_reg_c2_arr1_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr1_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr1_tg0_res[(LAYER3_BIT_SIZE*1)-2:(LAYER3_BIT_SIZE*0)];
        md.extracted_reg_c2_arr1_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr1_tg1_res[(LAYER3_BIT_SIZE*2)-2:(LAYER3_BIT_SIZE*1)];
        md.extracted_reg_c2_arr1_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
    }

    action extract_reg_c2_layer3_arr1_0111() {
        md.extracted_reg_c2_arr1_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr1_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr1_tg0_res[(LAYER3_BIT_SIZE*1)-2:(LAYER3_BIT_SIZE*0)];
        md.extracted_reg_c2_arr1_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr1_tg1_res[(LAYER3_BIT_SIZE*2)-2:(LAYER3_BIT_SIZE*1)];
        md.extracted_reg_c2_arr1_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr1_tg1_res[(LAYER3_BIT_SIZE*1)-2:(LAYER3_BIT_SIZE*0)];
    }

    action extract_reg_c2_layer3_arr1_1000() {
        md.extracted_reg_c2_arr1_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr1_tg0_res[(LAYER3_BIT_SIZE*2)-2:(LAYER3_BIT_SIZE*1)];
        md.extracted_reg_c2_arr1_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr1_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr1_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
    }

    action extract_reg_c2_layer3_arr1_1001() {
        md.extracted_reg_c2_arr1_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr1_tg0_res[(LAYER3_BIT_SIZE*2)-2:(LAYER3_BIT_SIZE*1)];
        md.extracted_reg_c2_arr1_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr1_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr1_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr1_tg1_res[(LAYER3_BIT_SIZE*1)-2:(LAYER3_BIT_SIZE*0)];
    }

    action extract_reg_c2_layer3_arr1_1010() {
        md.extracted_reg_c2_arr1_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr1_tg0_res[(LAYER3_BIT_SIZE*2)-2:(LAYER3_BIT_SIZE*1)];
        md.extracted_reg_c2_arr1_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr1_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr1_tg1_res[(LAYER3_BIT_SIZE*2)-2:(LAYER3_BIT_SIZE*1)];
        md.extracted_reg_c2_arr1_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
    }

    action extract_reg_c2_layer3_arr1_1011() {
        md.extracted_reg_c2_arr1_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr1_tg0_res[(LAYER3_BIT_SIZE*2)-2:(LAYER3_BIT_SIZE*1)];
        md.extracted_reg_c2_arr1_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr1_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr1_tg1_res[(LAYER3_BIT_SIZE*2)-2:(LAYER3_BIT_SIZE*1)];
        md.extracted_reg_c2_arr1_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr1_tg1_res[(LAYER3_BIT_SIZE*1)-2:(LAYER3_BIT_SIZE*0)];
    }

    action extract_reg_c2_layer3_arr1_1100() {
        md.extracted_reg_c2_arr1_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr1_tg0_res[(LAYER3_BIT_SIZE*2)-2:(LAYER3_BIT_SIZE*1)];
        md.extracted_reg_c2_arr1_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr1_tg0_res[(LAYER3_BIT_SIZE*1)-2:(LAYER3_BIT_SIZE*0)];
        md.extracted_reg_c2_arr1_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr1_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
    }

    action extract_reg_c2_layer3_arr1_1101() {
        md.extracted_reg_c2_arr1_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr1_tg0_res[(LAYER3_BIT_SIZE*2)-2:(LAYER3_BIT_SIZE*1)];
        md.extracted_reg_c2_arr1_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr1_tg0_res[(LAYER3_BIT_SIZE*1)-2:(LAYER3_BIT_SIZE*0)];
        md.extracted_reg_c2_arr1_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
        md.extracted_reg_c2_arr1_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr1_tg1_res[(LAYER3_BIT_SIZE*1)-2:(LAYER3_BIT_SIZE*0)];
    }

    action extract_reg_c2_layer3_arr1_1110() {
        md.extracted_reg_c2_arr1_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr1_tg0_res[(LAYER3_BIT_SIZE*2)-2:(LAYER3_BIT_SIZE*1)];
        md.extracted_reg_c2_arr1_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr1_tg0_res[(LAYER3_BIT_SIZE*1)-2:(LAYER3_BIT_SIZE*0)];
        md.extracted_reg_c2_arr1_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr1_tg1_res[(LAYER3_BIT_SIZE*2)-2:(LAYER3_BIT_SIZE*1)];
        md.extracted_reg_c2_arr1_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = 0;
    }

    action extract_reg_c2_layer3_arr1_1111() {
        md.extracted_reg_c2_arr1_slice0[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr1_tg0_res[(LAYER3_BIT_SIZE*2)-2:(LAYER3_BIT_SIZE*1)];
        md.extracted_reg_c2_arr1_slice1[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr1_tg0_res[(LAYER3_BIT_SIZE*1)-2:(LAYER3_BIT_SIZE*0)];
        md.extracted_reg_c2_arr1_slice2[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr1_tg1_res[(LAYER3_BIT_SIZE*2)-2:(LAYER3_BIT_SIZE*1)];
        md.extracted_reg_c2_arr1_slice3[LAYER1_BIT_SIZE+LAYER2_BIT_SIZE+LAYER3_BIT_SIZE-4:LAYER1_BIT_SIZE+LAYER2_BIT_SIZE-2] = reg_c2_layer3_arr1_tg1_res[(LAYER3_BIT_SIZE*1)-2:(LAYER3_BIT_SIZE*0)];
    }

    table extract_reg_c2_layer2_arr0 {
        key = {
            reg_c2_layer1_arr0_overflow_counter_res : exact;
        }
        actions = {
            extract_reg_c2_layer2_arr0_0000;
            extract_reg_c2_layer2_arr0_0001;
            extract_reg_c2_layer2_arr0_0010;
            extract_reg_c2_layer2_arr0_0011;
            extract_reg_c2_layer2_arr0_0100;
            extract_reg_c2_layer2_arr0_0101;
            extract_reg_c2_layer2_arr0_0110;
            extract_reg_c2_layer2_arr0_0111;
            extract_reg_c2_layer2_arr0_1000;
            extract_reg_c2_layer2_arr0_1001;
            extract_reg_c2_layer2_arr0_1010;
            extract_reg_c2_layer2_arr0_1011;
            extract_reg_c2_layer2_arr0_1100;
            extract_reg_c2_layer2_arr0_1101;
            extract_reg_c2_layer2_arr0_1110;
            extract_reg_c2_layer2_arr0_1111;
        }
    }

    table extract_reg_c2_layer2_arr1 {
        key = {
            reg_c2_layer1_arr1_overflow_counter_res : exact;
        }
        actions = {
            extract_reg_c2_layer2_arr1_0000;
            extract_reg_c2_layer2_arr1_0001;
            extract_reg_c2_layer2_arr1_0010;
            extract_reg_c2_layer2_arr1_0011;
            extract_reg_c2_layer2_arr1_0100;
            extract_reg_c2_layer2_arr1_0101;
            extract_reg_c2_layer2_arr1_0110;
            extract_reg_c2_layer2_arr1_0111;
            extract_reg_c2_layer2_arr1_1000;
            extract_reg_c2_layer2_arr1_1001;
            extract_reg_c2_layer2_arr1_1010;
            extract_reg_c2_layer2_arr1_1011;
            extract_reg_c2_layer2_arr1_1100;
            extract_reg_c2_layer2_arr1_1101;
            extract_reg_c2_layer2_arr1_1110;
            extract_reg_c2_layer2_arr1_1111;
        }
    }

    table extract_reg_c2_layer3_arr0 {
        key = {
            reg_c2_layer2_arr0_overflow_counter_res : exact;
        }
        actions = {
            extract_reg_c2_layer3_arr0_0000;
            extract_reg_c2_layer3_arr0_0001;
            extract_reg_c2_layer3_arr0_0010;
            extract_reg_c2_layer3_arr0_0011;
            extract_reg_c2_layer3_arr0_0100;
            extract_reg_c2_layer3_arr0_0101;
            extract_reg_c2_layer3_arr0_0110;
            extract_reg_c2_layer3_arr0_0111;
            extract_reg_c2_layer3_arr0_1000;
            extract_reg_c2_layer3_arr0_1001;
            extract_reg_c2_layer3_arr0_1010;
            extract_reg_c2_layer3_arr0_1011;
            extract_reg_c2_layer3_arr0_1100;
            extract_reg_c2_layer3_arr0_1101;
            extract_reg_c2_layer3_arr0_1110;
            extract_reg_c2_layer3_arr0_1111;
        }
    }

    table extract_reg_c2_layer3_arr1 {
        key = {
            reg_c2_layer2_arr1_overflow_counter_res : exact;
        }
        actions = {
            extract_reg_c2_layer3_arr1_0000;
            extract_reg_c2_layer3_arr1_0001;
            extract_reg_c2_layer3_arr1_0010;
            extract_reg_c2_layer3_arr1_0011;
            extract_reg_c2_layer3_arr1_0100;
            extract_reg_c2_layer3_arr1_0101;
            extract_reg_c2_layer3_arr1_0110;
            extract_reg_c2_layer3_arr1_0111;
            extract_reg_c2_layer3_arr1_1000;
            extract_reg_c2_layer3_arr1_1001;
            extract_reg_c2_layer3_arr1_1010;
            extract_reg_c2_layer3_arr1_1011;
            extract_reg_c2_layer3_arr1_1100;
            extract_reg_c2_layer3_arr1_1101;
            extract_reg_c2_layer3_arr1_1110;
            extract_reg_c2_layer3_arr1_1111;
        }
    }

    action set_layer1_overflow_flag_action() {
        layer1_overflow_flag = 1;
    }

    table reg_c2_layer1_overflow_table {
        key = {
            reg_c2_layer1_arr0_cur_res[(LAYER1_BIT_SIZE*4)-1:(LAYER1_BIT_SIZE*4)-1] : exact;
            reg_c2_layer1_arr0_cur_res[(LAYER1_BIT_SIZE*3)-1:(LAYER1_BIT_SIZE*3)-1] : exact;
            reg_c2_layer1_arr0_cur_res[(LAYER1_BIT_SIZE*2)-1:(LAYER1_BIT_SIZE*2)-1] : exact;
            reg_c2_layer1_arr0_cur_res[(LAYER1_BIT_SIZE*1)-1:(LAYER1_BIT_SIZE*1)-1] : exact;
            reg_c2_layer1_arr1_cur_res[(LAYER1_BIT_SIZE*4)-1:(LAYER1_BIT_SIZE*4)-1] : exact;
            reg_c2_layer1_arr1_cur_res[(LAYER1_BIT_SIZE*3)-1:(LAYER1_BIT_SIZE*3)-1] : exact;
            reg_c2_layer1_arr1_cur_res[(LAYER1_BIT_SIZE*2)-1:(LAYER1_BIT_SIZE*2)-1] : exact;
            reg_c2_layer1_arr1_cur_res[(LAYER1_BIT_SIZE*1)-1:(LAYER1_BIT_SIZE*1)-1] : exact;
        }
        actions = {
            set_layer1_overflow_flag_action;
        }
    }

    action set_layer2_overflow_flag_action() {
        layer2_overflow_flag = 1;
    }

    table reg_c2_layer2_overflow_table {
        key = {
            reg_c2_layer2_arr0_tg0_res[(LAYER2_BIT_SIZE*2)-1:(LAYER2_BIT_SIZE*2)-1]    : exact;
            reg_c2_layer2_arr0_tg0_res[(LAYER2_BIT_SIZE*1)-1:(LAYER2_BIT_SIZE*1)-1]    : exact;
            reg_c2_layer2_arr0_tg1_res[(LAYER2_BIT_SIZE*2)-1:(LAYER2_BIT_SIZE*2)-1]    : exact;
            reg_c2_layer2_arr0_tg1_res[(LAYER2_BIT_SIZE*1)-1:(LAYER2_BIT_SIZE*1)-1]    : exact;
            reg_c2_layer2_arr1_tg0_res[(LAYER2_BIT_SIZE*2)-1:(LAYER2_BIT_SIZE*2)-1]    : exact;
            reg_c2_layer2_arr1_tg0_res[(LAYER2_BIT_SIZE*1)-1:(LAYER2_BIT_SIZE*1)-1]    : exact;
            reg_c2_layer2_arr1_tg1_res[(LAYER2_BIT_SIZE*2)-1:(LAYER2_BIT_SIZE*2)-1]    : exact;
            reg_c2_layer2_arr1_tg1_res[(LAYER2_BIT_SIZE*1)-1:(LAYER2_BIT_SIZE*1)-1]    : exact;
        }
        actions = {
            set_layer2_overflow_flag_action;
        }
    }

    action set_layer3_overflow_tag_action(bit<9> tag) {
        layer3_overflow_tag = tag;
    }

    table reg_c2_layer3_overflow_table {
        key = {
            reg_c2_layer3_arr0_tg0_res[(LAYER3_BIT_SIZE*2)-1:(LAYER3_BIT_SIZE*2)-1]    : exact;
            reg_c2_layer3_arr0_tg0_res[(LAYER3_BIT_SIZE*1)-1:(LAYER3_BIT_SIZE*1)-1]    : exact;
            reg_c2_layer3_arr0_tg1_res[(LAYER3_BIT_SIZE*2)-1:(LAYER3_BIT_SIZE*2)-1]    : exact;
            reg_c2_layer3_arr0_tg1_res[(LAYER3_BIT_SIZE*1)-1:(LAYER3_BIT_SIZE*1)-1]    : exact;
            reg_c2_layer3_arr1_tg0_res[(LAYER3_BIT_SIZE*2)-1:(LAYER3_BIT_SIZE*2)-1]    : exact;
            reg_c2_layer3_arr1_tg0_res[(LAYER3_BIT_SIZE*1)-1:(LAYER3_BIT_SIZE*1)-1]    : exact;
            reg_c2_layer3_arr1_tg1_res[(LAYER3_BIT_SIZE*2)-1:(LAYER3_BIT_SIZE*2)-1]    : exact;
            reg_c2_layer3_arr1_tg1_res[(LAYER3_BIT_SIZE*1)-1:(LAYER3_BIT_SIZE*1)-1]    : exact;
        }
        actions = {
            set_layer3_overflow_tag_action;
        }
    }

    action reg_c2_layer1_arr0_w1_overflow_counter_update_action() {
        reg_c2_layer1_arr0_overflow_counter_res = reg_c2_layer1_arr0_w1_overflow_counter_update.execute(reg_c2_key_a[LAYER1_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer1_arr0_w1_overflow_counter_reset_action() {
        reg_c2_layer1_arr0_overflow_counter_res = reg_c2_layer1_arr0_w1_overflow_counter_reset.execute(reg_c2_key_a[LAYER1_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer1_arr0_w2_overflow_counter_update_action() {
        reg_c2_layer1_arr0_overflow_counter_res = reg_c2_layer1_arr0_w2_overflow_counter_update.execute(reg_c2_key_a[LAYER1_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer1_arr0_w2_overflow_counter_reset_action() {
        reg_c2_layer1_arr0_overflow_counter_res = reg_c2_layer1_arr0_w2_overflow_counter_reset.execute(reg_c2_key_a[LAYER1_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer1_arr1_w1_overflow_counter_update_action() {
        reg_c2_layer1_arr1_overflow_counter_res = reg_c2_layer1_arr1_w1_overflow_counter_update.execute(reg_c2_key_b[LAYER1_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer1_arr1_w1_overflow_counter_reset_action() {
        reg_c2_layer1_arr1_overflow_counter_res = reg_c2_layer1_arr1_w1_overflow_counter_reset.execute(reg_c2_key_b[LAYER1_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer1_arr1_w2_overflow_counter_update_action() {
        reg_c2_layer1_arr1_overflow_counter_res = reg_c2_layer1_arr1_w2_overflow_counter_update.execute(reg_c2_key_b[LAYER1_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer1_arr1_w2_overflow_counter_reset_action() {
        reg_c2_layer1_arr1_overflow_counter_res = reg_c2_layer1_arr1_w2_overflow_counter_reset.execute(reg_c2_key_b[LAYER1_ENTRY_SIZE_EXP-1:0]);
    }

    action reg_c2_layer2_arr0_w1_overflow_counter_update_action() {
        reg_c2_layer2_arr0_overflow_counter_res = reg_c2_layer2_arr0_w1_overflow_counter_update.execute(reg_c2_key_a[LAYER2_ENTRY_SIZE_EXP-1:0]) & reg_c2_layer1_arr0_overflow_counter_res;
    }

    action reg_c2_layer2_arr0_w1_overflow_counter_reset_action() {
        reg_c2_layer2_arr0_overflow_counter_res = reg_c2_layer2_arr0_w1_overflow_counter_reset.execute(reg_c2_key_a[LAYER2_ENTRY_SIZE_EXP-1:0]) & reg_c2_layer1_arr0_overflow_counter_res;
    }

    action reg_c2_layer2_arr0_w2_overflow_counter_update_action() {
        reg_c2_layer2_arr0_overflow_counter_res = reg_c2_layer2_arr0_w2_overflow_counter_update.execute(reg_c2_key_a[LAYER2_ENTRY_SIZE_EXP-1:0]) & reg_c2_layer1_arr0_overflow_counter_res;
    }

    action reg_c2_layer2_arr0_w2_overflow_counter_reset_action() {
        reg_c2_layer2_arr0_overflow_counter_res = reg_c2_layer2_arr0_w2_overflow_counter_reset.execute(reg_c2_key_a[LAYER2_ENTRY_SIZE_EXP-1:0]) & reg_c2_layer1_arr0_overflow_counter_res;
    }

    action reg_c2_layer2_arr1_w1_overflow_counter_update_action() {
        reg_c2_layer2_arr1_overflow_counter_res = reg_c2_layer2_arr1_w1_overflow_counter_update.execute(reg_c2_key_b[LAYER2_ENTRY_SIZE_EXP-1:0]) & reg_c2_layer1_arr1_overflow_counter_res;
    }

    action reg_c2_layer2_arr1_w1_overflow_counter_reset_action() {
        reg_c2_layer2_arr1_overflow_counter_res = reg_c2_layer2_arr1_w1_overflow_counter_reset.execute(reg_c2_key_b[LAYER2_ENTRY_SIZE_EXP-1:0]) & reg_c2_layer1_arr1_overflow_counter_res;
    }

    action reg_c2_layer2_arr1_w2_overflow_counter_update_action() {
        reg_c2_layer2_arr1_overflow_counter_res = reg_c2_layer2_arr1_w2_overflow_counter_update.execute(reg_c2_key_b[LAYER2_ENTRY_SIZE_EXP-1:0]) & reg_c2_layer1_arr1_overflow_counter_res;
    }

    action reg_c2_layer2_arr1_w2_overflow_counter_reset_action() {
        reg_c2_layer2_arr1_overflow_counter_res = reg_c2_layer2_arr1_w2_overflow_counter_reset.execute(reg_c2_key_b[LAYER2_ENTRY_SIZE_EXP-1:0]) & reg_c2_layer1_arr1_overflow_counter_res;
    }

    table reg_c2_layer1_arr0_overflow_counter_table {
        key = {
            global_time2                : exact;
            reg_c_timer2_arr0_diff      : exact;
        }
        actions = {
            reg_c2_layer1_arr0_w1_overflow_counter_update_action;
            reg_c2_layer1_arr0_w1_overflow_counter_reset_action;
            reg_c2_layer1_arr0_w2_overflow_counter_update_action;
            reg_c2_layer1_arr0_w2_overflow_counter_reset_action;
        }
    }

    table reg_c2_layer1_arr1_overflow_counter_table {
        key = {
            global_time2                : exact;
            reg_c_timer2_arr1_diff      : exact;
        }
        actions = {
            reg_c2_layer1_arr1_w1_overflow_counter_update_action;
            reg_c2_layer1_arr1_w1_overflow_counter_reset_action;
            reg_c2_layer1_arr1_w2_overflow_counter_update_action;
            reg_c2_layer1_arr1_w2_overflow_counter_reset_action;
        }
    }

    table reg_c2_layer2_arr0_overflow_counter_table {
        key = {
            global_time3                : exact;
            reg_c_timer3_arr0_diff      : exact;
        }
        actions = {
            reg_c2_layer2_arr0_w1_overflow_counter_update_action;
            reg_c2_layer2_arr0_w1_overflow_counter_reset_action;
            reg_c2_layer2_arr0_w2_overflow_counter_update_action;
            reg_c2_layer2_arr0_w2_overflow_counter_reset_action;
        }
    }

    table reg_c2_layer2_arr1_overflow_counter_table {
        key = {
            global_time3                : exact;
            reg_c_timer3_arr1_diff      : exact;
        }
        actions = {
            reg_c2_layer2_arr1_w1_overflow_counter_update_action;
            reg_c2_layer2_arr1_w1_overflow_counter_reset_action;
            reg_c2_layer2_arr1_w2_overflow_counter_update_action;
            reg_c2_layer2_arr1_w2_overflow_counter_reset_action;
        }
    }

    action send(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;

        hdr.overflow.setInvalid();
        hdr.decay_update.setInvalid();
        hdr.ethernet.ether_type = ether_type_t.IPV4;
    }

    action decay_recirculate(bit<4> decay_tag, bit<1> ingress_port_is_port_a, bit<1> ingress_port_is_management) {
        ig_tm_md.ucast_egress_port[8:7] = ig_intr_md.ingress_port[8:7];
        ig_tm_md.ucast_egress_port[6:0] = RECIRC_PORT;

        hdr.decay_update.setValid();
        hdr.ethernet.ether_type = ether_type_t.DECAY;
        hdr.decay_update.ether_type = ether_type_t.IPV4;

        hdr.decay_update.layer2_arr0_tg0_decay = reg_c2_layer2_arr0_tg0_res >> LAYER2_DECAY_BIT;
        hdr.decay_update.layer2_arr1_tg0_decay = reg_c2_layer2_arr1_tg0_res >> LAYER2_DECAY_BIT;
        hdr.decay_update.layer2_arr0_tg1_decay = reg_c2_layer2_arr0_tg1_res >> LAYER2_DECAY_BIT;
        hdr.decay_update.layer2_arr1_tg1_decay = reg_c2_layer2_arr1_tg1_res >> LAYER2_DECAY_BIT;
        hdr.decay_update.layer3_arr0_tg0_decay = reg_c2_layer3_arr0_tg0_res >> LAYER3_DECAY_BIT;
        hdr.decay_update.layer3_arr1_tg0_decay = reg_c2_layer3_arr1_tg0_res >> LAYER3_DECAY_BIT;
        hdr.decay_update.layer3_arr0_tg1_decay = reg_c2_layer3_arr0_tg1_res >> LAYER3_DECAY_BIT;
        hdr.decay_update.layer3_arr1_tg1_decay = reg_c2_layer3_arr1_tg1_res >> LAYER3_DECAY_BIT;

        // hdr.decay_update.layer2_arr0_tg0_decay[LAYER2_TOTAL_BIT_SIZE-1-LAYER2_DECAY_BIT:0] = reg_c2_layer2_arr0_tg0_res[LAYER2_TOTAL_BIT_SIZE-1:LAYER2_DECAY_BIT];
        // hdr.decay_update.layer2_arr1_tg0_decay[LAYER2_TOTAL_BIT_SIZE-1-LAYER2_DECAY_BIT:0] = reg_c2_layer2_arr1_tg0_res[LAYER2_TOTAL_BIT_SIZE-1:LAYER2_DECAY_BIT];
        // hdr.decay_update.layer2_arr0_tg1_decay[LAYER2_TOTAL_BIT_SIZE-1-LAYER2_DECAY_BIT:0] = reg_c2_layer2_arr0_tg1_res[LAYER2_TOTAL_BIT_SIZE-1:LAYER2_DECAY_BIT];
        // hdr.decay_update.layer2_arr1_tg1_decay[LAYER2_TOTAL_BIT_SIZE-1-LAYER2_DECAY_BIT:0] = reg_c2_layer2_arr1_tg1_res[LAYER2_TOTAL_BIT_SIZE-1:LAYER2_DECAY_BIT];
        // hdr.decay_update.layer3_arr0_tg0_decay[LAYER3_TOTAL_BIT_SIZE-1-LAYER3_DECAY_BIT:0] = reg_c2_layer3_arr0_tg0_res[LAYER3_TOTAL_BIT_SIZE-1:LAYER3_DECAY_BIT];
        // hdr.decay_update.layer3_arr1_tg0_decay[LAYER3_TOTAL_BIT_SIZE-1-LAYER3_DECAY_BIT:0] = reg_c2_layer3_arr1_tg0_res[LAYER3_TOTAL_BIT_SIZE-1:LAYER3_DECAY_BIT];
        // hdr.decay_update.layer3_arr0_tg1_decay[LAYER3_TOTAL_BIT_SIZE-1-LAYER3_DECAY_BIT:0] = reg_c2_layer3_arr0_tg1_res[LAYER3_TOTAL_BIT_SIZE-1:LAYER3_DECAY_BIT];
        // hdr.decay_update.layer3_arr1_tg1_decay[LAYER3_TOTAL_BIT_SIZE-1-LAYER3_DECAY_BIT:0] = reg_c2_layer3_arr1_tg1_res[LAYER3_TOTAL_BIT_SIZE-1:LAYER3_DECAY_BIT];

        hdr.decay_update.layer2_arr0_is_decay = decay_tag[3:3];
        hdr.decay_update.layer2_arr1_is_decay = decay_tag[2:2];
        hdr.decay_update.layer3_arr0_is_decay = decay_tag[1:1];
        hdr.decay_update.layer3_arr1_is_decay = decay_tag[0:0];

        hdr.decay_update.ingress_port_is_port_a = ingress_port_is_port_a;
        hdr.decay_update.ingress_port_is_management = ingress_port_is_management;
    }

    action overflow_recirculate(bit<1> ingress_port_is_port_a) {
        ig_tm_md.ucast_egress_port[8:7] = ig_intr_md.ingress_port[8:7];
        ig_tm_md.ucast_egress_port[6:0] = RECIRC_PORT;

        hdr.overflow.setValid();
        hdr.ethernet.ether_type = ether_type_t.OVERFLOW;
        hdr.overflow.ether_type = ether_type_t.IPV4;

        hdr.overflow.ingress_port_is_port_a = ingress_port_is_port_a;
    }

    action overflow_recirculate_and_mirror_to_CPU(bit<1> ingress_port_is_port_a) {
        ig_tm_md.ucast_egress_port[8:7] = ig_intr_md.ingress_port[8:7];
        ig_tm_md.ucast_egress_port[6:0] = RECIRC_PORT;

        hdr.overflow.setValid();
        hdr.ethernet.ether_type = ether_type_t.OVERFLOW;
        hdr.overflow.ether_type = ether_type_t.IPV4;

        hdr.overflow.ingress_port_is_port_a = ingress_port_is_port_a;

        ig_dprsr_md.mirror_type = MIRROR_TYPE;
        md.ing_mir_ses = MIRROR_SID;
        md.upload.upload_type = 7w0 ++ layer3_overflow_tag;
    }

    table ipv4_port_and_recirculate_mirror_table {
        key = {
            ig_intr_md.ingress_port                     : exact;

            reg_c_timer2_arr0_diff                      : exact;
            reg_c_timer2_arr1_diff                      : exact;
            reg_c_timer3_arr0_diff                      : exact;
            reg_c_timer3_arr1_diff                      : exact;
            hdr.decay_update.isValid()                  : exact;
            hdr.decay_update.ingress_port_is_port_a     : exact;
            hdr.decay_update.ingress_port_is_management : exact;

            layer1_overflow_flag                        : exact;
            layer2_overflow_flag                        : exact;
            layer3_overflow_tag[8:8]                    : exact;
            hdr.overflow.isValid()                      : exact;
            hdr.overflow.ingress_port_is_port_a         : exact;
        }
        actions = {
            send;
            drop;
            decay_recirculate;
            overflow_recirculate;
            overflow_recirculate_and_mirror_to_CPU;
        }
        size = 3200;    // 2048+1024+32+64
    }

    action block_threshold_arr0_slice0_set() {
        block_request_arr0_slice0 = 1;
    }

    table block_threshold_arr0_slice0_table {
        key = {
            md.extracted_reg_c2_arr0_slice0 : exact;
        }
        actions = {
            NoAction;
            block_threshold_arr0_slice0_set;
        }
        size = THRESHOLD_ICMPQ;
    }

    action block_threshold_arr0_slice1_set() {
        block_request_arr0_slice1 = 1;
    }

    table block_threshold_arr0_slice1_table {
        key = {
            md.extracted_reg_c2_arr0_slice1 : exact;
        }
        actions = {
            NoAction;
            block_threshold_arr0_slice1_set;
        }
        size = THRESHOLD_UDP;
    }

    action block_threshold_arr0_slice2_set() {
        block_request_arr0_slice2 = 1;
    }

    table block_threshold_arr0_slice2_table {
        key = {
            md.extracted_reg_c2_arr0_slice2 : exact;
        }
        actions = {
            NoAction;
            block_threshold_arr0_slice2_set;
        }
        size = THRESHOLD_DNSQ;
    }

    action block_threshold_arr0_slice3_set() {
        block_request_arr0_slice3 = 1;
    }

    table block_threshold_arr0_slice3_table {
        key = {
            md.extracted_reg_c2_arr0_slice3 : exact;
        }
        actions = {
            NoAction;
            block_threshold_arr0_slice3_set;
        }
        size = THRESHOLD_SYN;
    }

    action block_threshold_arr1_slice0_set() {
        block_request_arr1_slice0 = 1;
    }

    table block_threshold_arr1_slice0_table {
        key = {
            md.extracted_reg_c2_arr1_slice0 : exact;
        }
        actions = {
            NoAction;
            block_threshold_arr1_slice0_set;
        }
        size = THRESHOLD_ICMPQ;
    }

    action block_threshold_arr1_slice1_set() {
        block_request_arr1_slice1 = 1;
    }

    table block_threshold_arr1_slice1_table {
        key = {
            md.extracted_reg_c2_arr1_slice1 : exact;
        }
        actions = {
            NoAction;
            block_threshold_arr1_slice1_set;
        }
        size = THRESHOLD_UDP;
    }

    action block_threshold_arr1_slice2_set() {
        block_request_arr1_slice2 = 1;
    }

    table block_threshold_arr1_slice2_table {
        key = {
            md.extracted_reg_c2_arr1_slice2 : exact;
        }
        actions = {
            NoAction;
            block_threshold_arr1_slice2_set;
        }
        size = THRESHOLD_DNSQ;
    }

    action block_threshold_arr1_slice3_set() {
        block_request_arr1_slice3 = 1;
    }

    table block_threshold_arr1_slice3_table {
        key = {
            md.extracted_reg_c2_arr1_slice3 : exact;
        }
        actions = {
            NoAction;
            block_threshold_arr1_slice3_set;
        }
        size = THRESHOLD_SYN;
    }

    table block_threshold_table {
        key = {
            block_request_arr0_slice0   : exact;
            block_request_arr0_slice1   : exact;
            block_request_arr0_slice2   : exact;
            block_request_arr0_slice3   : exact;
            block_request_arr1_slice0   : exact;
            block_request_arr1_slice1   : exact;
            block_request_arr1_slice2   : exact;
            block_request_arr1_slice3   : exact;
        }
        actions = {
            drop;
        }
    }

    Register<bit<32>, bit<1>>(1) to_cpu_counter;
    RegisterAction<bit<32>, bit<1>, bit<32>>(to_cpu_counter) to_cpu_counter_update = {
        void apply(inout bit<32> value, out bit<32> read_value){
            value = value + 1;
        }
    };

    action to_cpu_counter_update_action() {
        to_cpu_counter_update.execute(0);
    }

    table to_cpu_counter_table {
        key = {
            ig_dprsr_md.mirror_type : exact;
            is_blocked              : exact;
        }
        actions = {
            to_cpu_counter_update_action;
        }
        const entries = {
            (MIRROR_TYPE, 0)    : to_cpu_counter_update_action();
        }
    }

    /* Define the processing algorithm here */
    apply {
        global_time1 = ig_prsr_md.global_tstamp[GLOBAL_TIME1:GLOBAL_TIME1];
        global_time2 = ig_prsr_md.global_tstamp[GLOBAL_TIME2:GLOBAL_TIME2];
        global_time3 = ig_prsr_md.global_tstamp[GLOBAL_TIME3:GLOBAL_TIME3];
        reg_global_time1_set_table.apply();
        reg_global_time2_set_table.apply();
        reg_global_time3_set_table.apply();

        if (hdr.ipv4.isValid()) {
            // Check blocklist and if blocked set flag and set as drop
            check_blocklist.apply();

            // Check packet type
            check_icmpq_table.apply();  // ICMP flood
            check_udp_table.apply();    // UDP flood
            check_dnsq_table.apply();   // DNS flood
            check_syn_table.apply();    // SYN flood

            @stage(0) {
                reg_c2_key_a = hash0.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr});
            }
            @stage(1) {
                reg_c2_key_b = hash1.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr});
            }

            // Update timer
            reg_c_timer1_arr0_table.apply();
            reg_c_timer1_arr1_table.apply();
            reg_c_timer2_arr0_table.apply();
            reg_c_timer2_arr1_table.apply();
            reg_c_timer2_arr0_diff = global_time2 ^ reg_c_timer2_arr0_res;
            reg_c_timer2_arr1_diff = global_time2 ^ reg_c_timer2_arr1_res;
            reg_c_timer3_arr0_table.apply();
            reg_c_timer3_arr1_table.apply();
            reg_c_timer3_arr0_diff = global_time3 ^ reg_c_timer3_arr0_res;
            reg_c_timer3_arr1_diff = global_time3 ^ reg_c_timer3_arr1_res;

            /******************** LAYER 1 *******************/
            // Prepare operands
            reg_c2_layer1_dyn_table.apply();

            // Update register
            if (global_time1 == 0) {
                reg_c2_layer1_arr0_w1_table.apply();
                reg_c2_layer1_arr0_w2_read_action();
                reg_c2_layer1_arr1_w1_table.apply();
                reg_c2_layer1_arr1_w2_read_action();
            } else {
                reg_c2_layer1_arr0_w1_read_action();
                reg_c2_layer1_arr0_w2_table.apply();
                reg_c2_layer1_arr1_w1_read_action();
                reg_c2_layer1_arr1_w2_table.apply();
            }

            // Get merged result and apply slicing
            extract_reg_c2_layer1();

            // check overflow
            reg_c2_layer1_overflow_table.apply();
            reg_c2_layer1_arr0_overflow_counter_table.apply();
            reg_c2_layer1_arr1_overflow_counter_table.apply();

            /******************** LAYER 2 *******************/
            // Prepare operands
            reg_c2_layer2_arr0_dyn_table.apply();
            reg_c2_layer2_arr1_dyn_table.apply();

            // Update register
            reg_c2_layer2_arr0_tg0_table.apply();
            reg_c2_layer2_arr0_tg1_table.apply();
            reg_c2_layer2_arr1_tg0_table.apply();
            reg_c2_layer2_arr1_tg1_table.apply();

            // Get merged result and apply slicing
            extract_reg_c2_layer2_arr0.apply();
            extract_reg_c2_layer2_arr1.apply();

            // check overflow
            reg_c2_layer2_overflow_table.apply();
            reg_c2_layer2_arr0_overflow_counter_table.apply();
            reg_c2_layer2_arr1_overflow_counter_table.apply();

            /******************** LAYER 3 *******************/
            // Prepare operands
            reg_c2_layer3_arr0_dyn_table.apply();
            reg_c2_layer3_arr1_dyn_table.apply();

            // Update register
            reg_c2_layer3_arr0_tg0_table.apply();
            reg_c2_layer3_arr0_tg1_table.apply();
            reg_c2_layer3_arr1_tg0_table.apply();
            reg_c2_layer3_arr1_tg1_table.apply();

            // Get merged result and apply slicing
            extract_reg_c2_layer3_arr0.apply();
            extract_reg_c2_layer3_arr1.apply();

            // check overflow
            reg_c2_layer3_overflow_table.apply();

            block_threshold_arr0_slice0_table.apply();
            block_threshold_arr0_slice1_table.apply();
            block_threshold_arr0_slice2_table.apply();
            block_threshold_arr0_slice3_table.apply();
            block_threshold_arr1_slice0_table.apply();
            block_threshold_arr1_slice1_table.apply();
            block_threshold_arr1_slice2_table.apply();
            block_threshold_arr1_slice3_table.apply();
            switch (ipv4_port_and_recirculate_mirror_table.apply().action_run) {
                send    : { block_threshold_table.apply(); }
            }
            to_cpu_counter_table.apply();
        }
    }
}

control IngressDeparser(packet_out                  pkt,
    /* User */
    inout ingress_headers_t                         hdr,
    in    ingress_metadata_t                        md,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
    Mirror() mirror;
    apply {
        if (ig_dprsr_md.mirror_type == MIRROR_TYPE) {
			mirror.emit<upload_h>(md.ing_mir_ses, md.upload);
		}
		pkt.emit(hdr);
    }
}



/*************************************************
 ****** E G R E S S    P R O C E S S I N G *******
 ************************************************/
struct egress_headers_t {}
struct egress_metadata_t {}

parser EgressParser(packet_in       pkt,
    out egress_headers_t            hdr,
    out egress_metadata_t           meta,
    out egress_intrinsic_metadata_t eg_intr_md)
{
    state start { pkt.extract(eg_intr_md); transition accept; }
}

control Egress(
    inout egress_headers_t                              hdr,
    inout egress_metadata_t                             meta,
    in    egress_intrinsic_metadata_t                   eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t       eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t      eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t   eg_oport_md)
{
    apply {}
}

control EgressDeparser(packet_out                   pkt,
    inout egress_headers_t                          hdr,
    in    egress_metadata_t                         meta,
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply { pkt.emit(hdr); }
}



/********** F I N A L    P A C K A G E **********/
Pipeline(
    IngressParser(), Ingress(), IngressDeparser(),
    EgressParser(), Egress(), EgressDeparser()
) pipe;

Switch(pipe) main;
