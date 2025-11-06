/* -*- P4_16 -*- */

#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#elif __TARGET_TOFINO__ == 1
#include <tna.p4>
#else
#error This P4 program supports only Tofino Native Architecture
#endif

/*******************************************
 **    CONSTANTS AND TYPES DEFINITIONS    **
 *******************************************/

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<128> ipv6_addr_t;
typedef bit<12> vlan_id_t;

typedef bit<16> ether_type_t;

const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_ARP = 16w0x0806;
const ether_type_t ETHERTYPE_IPV6 = 16w0x86dd;
const ether_type_t ETHERTYPE_VLAN = 16w0x8100;

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_ICMP = 1;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;


/*******************************************
 ********     HEADER DEFINITIONS    ********
 *******************************************/
header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header vlan_tag_h {
    bit<3> pcp;
    bit<1> cfi;
    vlan_id_t vid;
    bit<16> ether_type;
}

header mpls_h {
    bit<20> label;
    bit<3> exp;
    bit<1> bos;
    bit<8> ttl;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header ipv6_h {
    bit<4> version;
    bit<8> traffic_class;
    bit<20> flow_label;
    bit<16> payload_len;
    bit<8> next_hdr;
    bit<8> hop_limit;
    ipv6_addr_t src_addr;
    ipv6_addr_t dst_addr;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
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
    bit<8> type_;
    bit<8> code;
    bit<16> hdr_checksum;
}

// Address Resolution Protocol -- RFC 6747
header arp_h {
    bit<16> hw_type;
    bit<16> proto_type;
    bit<8> hw_addr_len;
    bit<8> proto_addr_len;
    bit<16> opcode;
    // ...
}

// Segment Routing Extension (SRH) -- IETFv7
header ipv6_srh_h {
    bit<8> next_hdr;
    bit<8> hdr_ext_len;
    bit<8> routing_type;
    bit<8> seg_left;
    bit<8> last_entry;
    bit<8> flags;
    bit<16> tag;
}

// VXLAN -- RFC 7348
header vxlan_h {
    bit<8> flags;
    bit<24> reserved;
    bit<24> vni;
    bit<8> reserved2;
}

// Generic Routing Encapsulation (GRE) -- RFC 1701
header gre_h {
    bit<1> C;
    bit<1> R;
    bit<1> K;
    bit<1> S;
    bit<1> s;
    bit<3> recurse;
    bit<5> flags;
    bit<3> version;
    bit<16> proto;
}

header resubmit_type_c {
    bit<8>  type;
    bit<32> f1;
    bit<16> f2;
    bit<8> f3;
}

@pa_container_size("ingress", "md.c.type", 8)
@pa_container_size("ingress", "md.c.f1", 32)
@pa_container_size("ingress", "md.c.f2", 16)
@pa_container_size("ingress", "md.c.f3", 8)
//@pa_container_size("ingress", "md.c.padding", 8)

const bit<32> SIZE16 = 0x0000ffff;
const bit<32> SIZE17 = 0x0001ffff;
const bit<32> SIZE18 = 0x0003ffff;
const bit<32> SIZE19 = 0x0007ffff;
const bit<32> SIZE20 = 0x000fffff;
const bit<3> DPRSR_DIGEST_TYPE_A = 3;
const bit<8> RESUB_TYPE_C = 1;

header port_metadata {
    bit<8>  type;
    bit<32> f1;
    bit<16> f2;
    bit<8> f3;
}

struct metadata_t { 
    port_metadata   port_md;
    bit<8>          resub_type;
    bit<16>         upload_meta;
    resubmit_type_c a;
    MirrorId_t ing_mir_ses; 
    bit<32> extracted_reg_c2_res_slice0;
    bit<32> extracted_reg_c2_res_slice1;
    bit<32> extracted_reg_c2_res_slice2;
    bit<32> extracted_reg_c2_res_slice3;
    bit<32> extracted_reg_c5_res_slice0;
    bit<32> extracted_reg_c5_res_slice1;
    bit<32> extracted_reg_c5_res_slice2;
    bit<32> extracted_reg_c5_res_slice3;
}

header upload_h {
    // bit<2>  pkt_type;
	bit<16> upload_type;
}

struct headers_t {
    ethernet_h ethernet;
    vlan_tag_h vlan_tag;
    ipv4_h ipv4;
    ipv6_h ipv6;
    icmp_h icmp;
    tcp_h tcp;
    udp_h udp;
    // Add more headers here.
    upload_h upload;
}


/****************************************
 ********    INGRESS PIPELINE    ********
 ****************************************/

// Ingress Parser
parser SwitchIngressParser(
        packet_in pkt,
        out headers_t hdr,
        out metadata_t md,
        out ingress_intrinsic_metadata_t ig_intr_md) {
	
    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            0 : parse_port_metadata;
            1 : parse_resubmit;
        }
    }
	state parse_port_metadata {
        md.port_md = port_metadata_unpack<port_metadata>(pkt);
        transition parse_ethernet;
    }

    state parse_resubmit {
        md.resub_type = pkt.lookahead<bit<8>>()[7:0];
        transition parse_resub_c;
    }
    state parse_resub_c {
        pkt.extract(md.a);
		//pkt.advance(32);
        transition parse_ethernet;
    }
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type){
			ETHERTYPE_IPV4: parse_ipv4;
			default: reject;
		}
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
			1: parse_icmp;
			IP_PROTOCOLS_TCP: parse_tcp;
			IP_PROTOCOLS_UDP: parse_udp;
			default: accept;
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

control SwitchIngress(
    inout headers_t hdr,
    inout metadata_t md,
    in ingress_intrinsic_metadata_t ig_intr_md,
    in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    // Timestamp bit 
    bit<1> global_time1 = 0; // 32 seconds interval
    bit<1> global_time2 = 0; // 8 seconds interval
    
    // Flags
    bit<1> is_blocked = 0;
    bit<1> icmpq_flag = 0;
    bit<1> icmpr_flag = 0;
    bit<1> udp_flag = 0;
    bit<1> dnsq_flag = 0;
    bit<1> dnsr_flag = 0;
    bit<1> coremelt_flag = 0;
    bit<1> syn_flag = 0;

    // bit<32> reg_c2_overflow_flag = 0;
    bit<32> reg_c2_overflow_flag_arr0 = 0;
    bit<32> reg_c2_overflow_flag_arr1 = 0;
    bit<32> reg_c2_overflow_flag_arr2 = 0;

    // Temporaral storage
    bit<1> orbit = 0;
    bit<32> reg_c2_toupdate_value = 32w0;
    bit<32> reg_c2_key_a = 0;
    bit<32> reg_c2_key_b = 0;
    bit<32> reg_c2_key_0 = 0;
    bit<32> reg_c2_key_1 = 0;
    bit<32> reg_c2_key_2 = 0;
    bit<32> reg_c2_cur_res_0 = 0;
    bit<32> reg_c2_cur_res_1 = 0;
    bit<32> reg_c2_cur_res_2 = 0;
    bit<32> reg_c2_res_0 = 0;
    bit<32> reg_c2_res_1 = 0;
    bit<32> reg_c2_res_2 = 0;

    bit<1> reg_c_timer1_res = 0;
    bit<1> reg_c_timer2_res = 0;


    // Memory Slicing result from reg_c2 count-min sketch
    // 4 INM tasks in reg_c2 (32 bits), each have 8 bits for initial value.
    // No isolation bit in current desig (i.e., the irst bit of each slices mean carry bit).
    // Due to adaptive memory slicing, the size of slices can be changed.

    // Slice 0 - App 0
    bit<32> extracted_reg_c2_res_slice0_arr0 = 0;
    bit<32> extracted_reg_c2_res_slice0_arr1 = 0;
    bit<32> extracted_reg_c2_res_slice0_arr2 = 0;

    // Slice 1 - App 1
    bit<32> extracted_reg_c2_res_slice1_arr0 = 0;
    bit<32> extracted_reg_c2_res_slice1_arr1 = 0;
    bit<32> extracted_reg_c2_res_slice1_arr2 = 0;

    // Slice 2 - App 2
    bit<32> extracted_reg_c2_res_slice2_arr0 = 0;
    bit<32> extracted_reg_c2_res_slice2_arr1 = 0;
    bit<32> extracted_reg_c2_res_slice2_arr2 = 0;

    // Slice 3 - App 3
    bit<32> extracted_reg_c2_res_slice3_arr0 = 0;
    bit<32> extracted_reg_c2_res_slice3_arr1 = 0;
    bit<32> extracted_reg_c2_res_slice3_arr2 = 0;

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
    ) crc32d;

    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, crc32) hash0;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, crc32d) hash1;
    // Hash<bit<32>>(HashAlgorithm_t.CUSTOM, crc32) hash2;
    // Hash<bit<32>>(HashAlgorithm_t.CUSTOM, crc32d) hash3;
    // Hash<bit<32>>(HashAlgorithm_t.CUSTOM, CRC32) hash4;
    // Hash<bit<32>>(HashAlgorithm_t.CUSTOM, CRC32) hash5;
    // bit<32> cms_0 = 32w12345; // Add constant for hash
    // bit<32> cms_1 = 32w34567;
    // bit<32> cms_2 = 32w56789;


    // Registers and following RegisterActions
    Register<bit<32>, bit<32>>(32w65536) reg_c2_w1_0;
    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c2_w1_0) reg_c2_w1_0_plus = {
        void apply(inout bit<32> value, out bit<32> read_value){
            value = value + reg_c2_toupdate_value;
            read_value = value;
        }
    };
    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c2_w1_0) reg_c2_w1_0_minus = {
        void apply(inout bit<32> value, out bit<32> read_value){
            value = value - reg_c2_toupdate_value;
            read_value = value;
        }
    };
    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c2_w1_0) reg_c2_w1_0_setbit = {
        void apply(inout bit<32> value, out bit<32> read_value){
            if(ig_intr_md.resubmit_flag == 1)
                value = value & reg_c2_toupdate_value;
            else
                value = reg_c2_toupdate_value; //equal to update
            read_value = value;
        }
    };
    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c2_w1_0) reg_c2_w1_0_read = {
        void apply(inout bit<32> value, out bit<32> read_value){
            read_value = value;
        }
    };

    Register<bit<32>, bit<32>>(32w65536) reg_c2_w1_1;
    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c2_w1_1) reg_c2_w1_1_plus = {
        void apply(inout bit<32> value, out bit<32> read_value){
            value = value + reg_c2_toupdate_value;
            read_value = value;
        }
    };
    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c2_w1_1) reg_c2_w1_1_minus = {
        void apply(inout bit<32> value, out bit<32> read_value){
            value = value - reg_c2_toupdate_value;
            read_value = value;
        }
    };
    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c2_w1_1) reg_c2_w1_1_setbit = {
        void apply(inout bit<32> value, out bit<32> read_value){
            if(ig_intr_md.resubmit_flag == 1)
                value = value & reg_c2_toupdate_value;
            else
                value = reg_c2_toupdate_value; //equal to update
            read_value = value;
        }
    };
    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c2_w1_1) reg_c2_w1_1_read = {
        void apply(inout bit<32> value, out bit<32> read_value){
            read_value = value;
        }
    };

    Register<bit<32>, bit<32>>(32w65536) reg_c2_w1_2;
    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c2_w1_2) reg_c2_w1_2_plus = {
        void apply(inout bit<32> value, out bit<32> read_value){
            value = value + reg_c2_toupdate_value;
            read_value = value;
        }
    };
    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c2_w1_2) reg_c2_w1_2_minus = {
        void apply(inout bit<32> value, out bit<32> read_value){
            value = value - reg_c2_toupdate_value;
            read_value = value;
        }
    };
    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c2_w1_2) reg_c2_w1_2_setbit = {
        void apply(inout bit<32> value, out bit<32> read_value){
            if(ig_intr_md.resubmit_flag == 1)
                value = value & reg_c2_toupdate_value;
            else
                value = reg_c2_toupdate_value; //equal to update
            read_value = value;
        }
    };
    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c2_w1_2) reg_c2_w1_2_read = {
        void apply(inout bit<32> value, out bit<32> read_value){
            read_value = value;
        }
    };

    Register<bit<32>, bit<32>>(32w65536) reg_c2_w2_0;
    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c2_w2_0) reg_c2_w2_0_plus = {
        void apply(inout bit<32> value, out bit<32> read_value){
            value = value + reg_c2_toupdate_value;
            read_value = value;
        }
    };
    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c2_w2_0) reg_c2_w2_0_minus = {
        void apply(inout bit<32> value, out bit<32> read_value){
            value = value - reg_c2_toupdate_value;
            read_value = value;
        }
    };
    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c2_w2_0) reg_c2_w2_0_setbit = {
        void apply(inout bit<32> value, out bit<32> read_value){
            if(ig_intr_md.resubmit_flag == 1)
                value = value & reg_c2_toupdate_value;
            else
                value = reg_c2_toupdate_value; //equal to update
            read_value = value;
        }
    };
    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c2_w2_0) reg_c2_w2_0_read = {
        void apply(inout bit<32> value, out bit<32> read_value){
            read_value = value;
        }
    };

    Register<bit<32>, bit<32>>(32w65536) reg_c2_w2_1;
    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c2_w2_1) reg_c2_w2_1_plus = {
        void apply(inout bit<32> value, out bit<32> read_value){
            value = value + reg_c2_toupdate_value;
            read_value = value;
        }
    };
    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c2_w2_1) reg_c2_w2_1_minus = {
        void apply(inout bit<32> value, out bit<32> read_value){
            value = value - reg_c2_toupdate_value;
            read_value = value;
        }
    };
    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c2_w2_1) reg_c2_w2_1_setbit = {
        void apply(inout bit<32> value, out bit<32> read_value){
            if(ig_intr_md.resubmit_flag == 1)
                value = value & reg_c2_toupdate_value;
            else
                value = reg_c2_toupdate_value; //equal to update
            read_value = value;
        }
    };
    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c2_w2_1) reg_c2_w2_1_read = {
        void apply(inout bit<32> value, out bit<32> read_value){
            read_value = value;
        }
    };
    Register<bit<32>, bit<32>>(32w65536) reg_c2_w2_2;
    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c2_w2_2) reg_c2_w2_2_plus = {
        void apply(inout bit<32> value, out bit<32> read_value){
            value = value + reg_c2_toupdate_value;
            read_value = value;
        }
    };
    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c2_w2_2) reg_c2_w2_2_minus = {
        void apply(inout bit<32> value, out bit<32> read_value){
            value = value - reg_c2_toupdate_value;
            read_value = value;
        }
    };
    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c2_w2_2) reg_c2_w2_2_setbit = {
        void apply(inout bit<32> value, out bit<32> read_value){
            if(ig_intr_md.resubmit_flag == 1)
                value = value & reg_c2_toupdate_value;
            else
                value = reg_c2_toupdate_value; //equal to update
            read_value = value;
        }
    };
    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_c2_w2_2) reg_c2_w2_2_read = {
        void apply(inout bit<32> value, out bit<32> read_value){
            read_value = value;
        }
    };

    Register<bit<1>, bit<32>>(32w65536) reg_c_timer1;
    RegisterAction<bit<1>, bit<32>, bit<1>>(reg_c_timer1) reg_c_timer1_update0 = {
        void apply(inout bit<1> value, out bit<1> read_value){
            read_value = value;
            value = 0;
        }
    };

    RegisterAction<bit<1>, bit<32>, bit<1>>(reg_c_timer1) reg_c_timer1_update1 = {
        void apply(inout bit<1> value, out bit<1> read_value){
            read_value = value;
            value = 1;
        }
    };

    Register<bit<1>, bit<32>>(32w65536) reg_c_timer2;
    RegisterAction<bit<1>, bit<32>, bit<1>>(reg_c_timer2) reg_c_timer2_update0 = {
        void apply(inout bit<1> value, out bit<1> read_value){
            read_value = value;
            value = 0;
        }
    };

    RegisterAction<bit<1>, bit<32>, bit<1>>(reg_c_timer2) reg_c_timer2_update1 = {
        void apply(inout bit<1> value, out bit<1> read_value){
            read_value = value;
            value = 1;
        }
    };

    // Register for get current time in CP,
    // Note that the current Python grpc API can not access ingress_prsr_md.global_tstamp
    // See DRV-6462
    Register<bit<1>, bit<1>>(1) global_time1_reg;
    RegisterAction<bit<1>, bit<1>, bit<1>>(global_time1_reg) global_time1_set1 = {
        void apply(inout bit<1> value, out bit<1> read_value){
            value = 1;
            read_value = value;
        }
    };
    RegisterAction<bit<1>, bit<1>, bit<1>>(global_time1_reg) global_time1_set0 = {
        void apply(inout bit<1> value, out bit<1> read_value){
            value = 0;
            read_value = value;
        }
    };

    action set_global_time1_action(bit<1> flag){
        global_time1 = flag;
        // hdr.upload.upload_type = 0;
    }

    table set_global_time1_table {
        key = {
            // ig_prsr_md.global_tstamp[32:32]: exact;
            //about 8 seconds
            ig_prsr_md.global_tstamp[33:33]: exact;
            //about 32 seconds
            // ig_prsr_md.global_tstamp[35:35]: exact;
            //about 32 seconds
            // ig_prsr_md.global_tstamp[38:38]: exact;
        }
        actions = {
            set_global_time1_action;
        }
    }




    // Check ICMP
    action check_icmpq_setflag(){
	    icmpq_flag = 1;
    }

    action check_icmpr_setflag(){
        icmpr_flag = 1;
    }

    table check_icmp_table{
        key = {
            hdr.icmp.isValid(): exact;
            hdr.icmp.type_: exact;
        }
        actions = {
            check_icmpr_setflag;
            check_icmpq_setflag;
        }
    }

    // action check_coremelt_setflag(){
    //     coremelt_flag = 1;
    // }

    // table check_coremelt_table{
    //     key = {
    //         hdr.ipv4.isValid(): exact;
    //     }
    //     actions = {
    //         check_coremelt_setflag;
    //     }
    // }

    action check_udp_setflag(){
        udp_flag = 1;
    }

    table check_udp_table{
        key = {
            hdr.udp.isValid(): exact;
        }
        actions = {
            check_udp_setflag;
        }
    }

    action check_dnsq_setflag(){
        dnsq_flag = 1;
        // orbit = 1;
    }

    action check_dnsr_setflag(){
        dnsr_flag = 1;
        // orbit = 1;
    }

    table check_dns_q_table{
        key = {
            hdr.ipv4.protocol: exact;
            hdr.udp.dst_port: exact;
        }
        actions = {
            check_dnsq_setflag;
        }
    }

    action check_syn_setflag(){
        // orbit = 1;
        syn_flag = 1;
    }

    table check_syn_table{
        key = {
            hdr.ipv4.protocol: exact;
            hdr.tcp.isValid(): exact;
            hdr.tcp.flags: exact;
        }
        actions = {
            check_syn_setflag;
        }
    }

    action reg_c2_merge(bit<32> slices){
        reg_c2_toupdate_value = slices;
    }

    action reg_c2_merge1(bit<32> slices){
        reg_c2_toupdate_value = reg_c2_toupdate_value + slices;
    }

    action reg_c2_reset(bit<32> slices){
        reg_c2_toupdate_value = slices;
    }

    table reg_c2_dyn_table{
        key = {
            icmpq_flag: exact;
            udp_flag: exact;
            syn_flag: exact;
            dnsq_flag: exact;
            ig_intr_md.resubmit_flag: exact;
            global_time1: exact;
        }
        actions = {
            reg_c2_merge;
            reg_c2_merge1;
            reg_c2_reset;
        }
    }

    action reg_c_timer1_update0_action(){
        reg_c_timer1_res = reg_c_timer1_update0.execute(reg_c2_key_0);
    }

    action reg_c_timer1_update1_action(){
        reg_c_timer1_res = reg_c_timer1_update1.execute(reg_c2_key_0);
    }

    table reg_c_timer1_table{

        key = {
            global_time1: exact;
        }

        actions = {
            reg_c_timer1_update0_action;
            reg_c_timer1_update1_action;
        }
    }

    action global_time1_set0_action(){
        global_time1_set0.execute(0);
    }

    action global_time1_set1_action(){
        global_time1_set1.execute(0);
    }

    table global_time1_reg_set_table{
        key = {
            global_time1: exact;
        }
        actions = {
            global_time1_set0_action;
            global_time1_set1_action;
        }
    }

    action drop_packet(){
        is_blocked = 1;
        ig_dprsr_md.drop_ctl=1;
    }

    table check_blocklist{
        key = {
            hdr.ipv4.src_addr: exact;
            hdr.ipv4.dst_addr: exact;
        }
        actions = {
            drop_packet;
        }
        size = 131072; // 2^17
    }

    action reg_c2_w1_0_plus_action(){
        reg_c2_cur_res_0 = reg_c2_w1_0_plus.execute(reg_c2_key_0);
    }

    action reg_c2_w1_1_plus_action(){
        reg_c2_cur_res_1 = reg_c2_w1_1_plus.execute(reg_c2_key_1);
    }

    action reg_c2_w1_2_plus_action(){
        reg_c2_cur_res_2 = reg_c2_w1_2_plus.execute(reg_c2_key_2);
    }

    action reg_c2_w1_0_minus_action(){
        reg_c2_w1_0_minus.execute(reg_c2_key_0);
    }

    action reg_c2_w1_1_minus_action(){
        reg_c2_w1_1_minus.execute(reg_c2_key_1);
    }

    action reg_c2_w1_2_minus_action(){
        reg_c2_w1_2_minus.execute(reg_c2_key_2);
    }

    action reg_c2_w1_0_setbit_action(){
        reg_c2_cur_res_0 = reg_c2_w1_0_setbit.execute(reg_c2_key_0);
    }

    action reg_c2_w1_1_setbit_action(){
        reg_c2_cur_res_1 = reg_c2_w1_1_setbit.execute(reg_c2_key_1);
    }

    action reg_c2_w1_2_setbit_action(){
        reg_c2_cur_res_2 = reg_c2_w1_2_setbit.execute(reg_c2_key_2);
    }

    action reg_c2_w1_0_read_action(){
        reg_c2_res_0 = reg_c2_w1_0_read.execute(reg_c2_key_0);
    }

    action reg_c2_w1_1_read_action(){
        reg_c2_res_1 = reg_c2_w1_1_read.execute(reg_c2_key_1);
    }

    action reg_c2_w1_2_read_action(){
        reg_c2_res_2 = reg_c2_w1_2_read.execute(reg_c2_key_2);
    }

    action reg_c2_w2_0_plus_action(){
        reg_c2_cur_res_0 = reg_c2_w2_0_plus.execute(reg_c2_key_0);
    }

    action reg_c2_w2_1_plus_action(){
        reg_c2_cur_res_1 = reg_c2_w2_1_plus.execute(reg_c2_key_1);
    }

    action reg_c2_w2_2_plus_action(){
        reg_c2_cur_res_2 = reg_c2_w2_2_plus.execute(reg_c2_key_2);
    }

    action reg_c2_w2_0_minus_action(){
        reg_c2_w2_0_minus.execute(reg_c2_key_0);
    }

    action reg_c2_w2_1_minus_action(){
        reg_c2_w2_1_minus.execute(reg_c2_key_1);
    }

    action reg_c2_w2_2_minus_action(){
        reg_c2_w2_2_minus.execute(reg_c2_key_2);
    }

    action reg_c2_w2_0_setbit_action(){
        reg_c2_cur_res_0 = reg_c2_w2_0_setbit.execute(reg_c2_key_0);
    }

    action reg_c2_w2_1_setbit_action(){
        reg_c2_cur_res_1 = reg_c2_w2_1_setbit.execute(reg_c2_key_1);
    }

    action reg_c2_w2_2_setbit_action(){
        reg_c2_cur_res_2 = reg_c2_w2_2_setbit.execute(reg_c2_key_2);
    }

    action reg_c2_w2_0_read_action(){
        reg_c2_cur_res_0 = reg_c2_w2_0_read.execute(reg_c2_key_0);
    }

    action reg_c2_w2_1_read_action(){
        reg_c2_cur_res_1 = reg_c2_w2_1_read.execute(reg_c2_key_1);
    }

    action reg_c2_w2_2_read_action(){
        reg_c2_cur_res_2 = reg_c2_w2_2_read.execute(reg_c2_key_2);
    }

    table reg_c2_w1_0_table{

        key = {
            global_time1: exact;
            reg_c_timer1_res: exact;
            ig_intr_md.resubmit_flag: exact;
        }

        actions = {
            reg_c2_w1_0_plus_action;
            reg_c2_w1_0_minus_action;
            reg_c2_w1_0_setbit_action;
            reg_c2_w1_0_read_action;
        }
    }

    table reg_c2_w1_1_table{

        key = {
            global_time1: exact;
            reg_c_timer1_res: exact;
            ig_intr_md.resubmit_flag: exact;
        }

        actions = {
            reg_c2_w1_1_plus_action;
            reg_c2_w1_1_minus_action;
            reg_c2_w1_1_setbit_action;
            reg_c2_w1_1_read_action;
        }
    }

    table reg_c2_w1_2_table{

        key = {
            global_time1: exact;
            reg_c_timer1_res: exact;
            ig_intr_md.resubmit_flag: exact;
        }

        actions = {
            reg_c2_w1_2_plus_action;
            reg_c2_w1_2_minus_action;
            reg_c2_w1_2_setbit_action;
            reg_c2_w1_2_read_action;
        }
    }

    table reg_c2_w2_0_table{

        key = {
            global_time1: exact;
            reg_c_timer1_res: exact;
            ig_intr_md.resubmit_flag: exact;
        }

        actions = {
            reg_c2_w2_0_plus_action;
            reg_c2_w2_0_minus_action;
            reg_c2_w2_0_setbit_action;
            reg_c2_w2_0_read_action;
        }
    }

    table reg_c2_w2_1_table{

        key = {
            global_time1: exact;
            reg_c_timer1_res: exact;
            ig_intr_md.resubmit_flag: exact;
        }

        actions = {
            reg_c2_w2_1_plus_action;
            reg_c2_w2_1_minus_action;
            reg_c2_w2_1_setbit_action;
            reg_c2_w2_1_read_action;
        }
    }

    table reg_c2_w2_2_table{

        key = {
            global_time1: exact;
            reg_c_timer1_res: exact;
            ig_intr_md.resubmit_flag: exact;
        }

        actions = {
            reg_c2_w2_2_plus_action;
            reg_c2_w2_2_minus_action;
            reg_c2_w2_2_setbit_action;
            reg_c2_w2_2_read_action;
        }
    }

    action extract_reg_c2_slicing_action(bit<32> mask1, bit<32> mask2, bit<32> mask3, bit<32> mask4, bit<32> mask5){
		reg_c2_overflow_flag_arr0 = reg_c2_cur_res_0 & mask1;
        reg_c2_overflow_flag_arr1 = reg_c2_cur_res_1 & mask1;
        reg_c2_overflow_flag_arr2 = reg_c2_cur_res_2 & mask1;

		extracted_reg_c2_res_slice0_arr0 = reg_c2_cur_res_0 & mask2;
        extracted_reg_c2_res_slice0_arr1 = reg_c2_cur_res_1 & mask2;
        extracted_reg_c2_res_slice0_arr2 = reg_c2_cur_res_2 & mask2;

		extracted_reg_c2_res_slice1_arr0 = reg_c2_cur_res_0 & mask3;
        extracted_reg_c2_res_slice1_arr1 = reg_c2_cur_res_1 & mask3;
        extracted_reg_c2_res_slice1_arr2 = reg_c2_cur_res_2 & mask3;

		extracted_reg_c2_res_slice2_arr0 = reg_c2_cur_res_0 & mask4;
        extracted_reg_c2_res_slice2_arr1 = reg_c2_cur_res_1 & mask4;
        extracted_reg_c2_res_slice2_arr2 = reg_c2_cur_res_2 & mask4;

		extracted_reg_c2_res_slice3_arr0 = reg_c2_cur_res_0 & mask5;
        extracted_reg_c2_res_slice3_arr1 = reg_c2_cur_res_1 & mask5;
        extracted_reg_c2_res_slice3_arr2 = reg_c2_cur_res_2 & mask5;
    }

    table reg_c2_slicing_table{
        key = {
            icmpq_flag: exact;
            udp_flag: exact;
            syn_flag: exact;
            dnsq_flag: exact;
            global_time1: exact;
        }

        actions = {
            extract_reg_c2_slicing_action;
        }
    }

    action cms_stage_1_action (){
        md.extracted_reg_c2_res_slice0 = min(extracted_reg_c2_res_slice0_arr0, extracted_reg_c2_res_slice0_arr1);
        md.extracted_reg_c2_res_slice1 = min(extracted_reg_c2_res_slice1_arr0, extracted_reg_c2_res_slice1_arr1);
        md.extracted_reg_c2_res_slice2 = min(extracted_reg_c2_res_slice2_arr0, extracted_reg_c2_res_slice2_arr1);
        md.extracted_reg_c2_res_slice3 = min(extracted_reg_c2_res_slice3_arr0, extracted_reg_c2_res_slice3_arr1);
    }

    table cms_stage_1{
        actions = {
            cms_stage_1_action;
        }
    }

    action cms_stage_2_action (){
        md.extracted_reg_c2_res_slice0 = min(md.extracted_reg_c2_res_slice0, extracted_reg_c2_res_slice0_arr2);        
        md.extracted_reg_c2_res_slice1 = min(md.extracted_reg_c2_res_slice1, extracted_reg_c2_res_slice1_arr2);
        md.extracted_reg_c2_res_slice2 = min(md.extracted_reg_c2_res_slice2, extracted_reg_c2_res_slice2_arr2);
        md.extracted_reg_c2_res_slice3 = min(md.extracted_reg_c2_res_slice3, extracted_reg_c2_res_slice3_arr2);
    }

    table cms_stage_2{
        actions = {
            cms_stage_2_action;
        }
    }
    
    bit<1> overflow_flag = 0;
    bit<16> mirror_tag = 0;
    action set_mirror_flag_action(bit<16> tag){
        overflow_flag = 1;
        mirror_tag = tag;
    }

    // NOTE: If one of the reg_c2_overflow_flag is not 0, set the overflow flag
    // key must be defined on Control Plane like below example
    // (e.g., 0x80808080 = all task overflowed, 0x80000000 = task 0 overflowed)
    // Action tag: 0b1xxxxxxxx : current window tag
    //             0bx111xxxxx : overflowed cms array tag
    //             0bxxxxx1111 : overflowed task tag
    // All combination need to be defined in the table
    table reg_c2_overflow_table{
        key = {
            reg_c2_overflow_flag_arr0: exact;
            reg_c2_overflow_flag_arr1: exact;
            reg_c2_overflow_flag_arr2: exact;
            global_time1: exact;
        }
        actions = {
            set_mirror_flag_action;
        }
        size = 10000; // 8190 entries: 8192 - 2 (all flag = 0 w/ global time [1,0])
    }

    // table in_dp_filter{
    //     key = {
    //         md.extracted_reg_c2_res_slice0: exact;
    //         md.extracted_reg_c2_res_slice1: exact;
    //         md.extracted_reg_c2_res_slice2: exact;
    //         md.extracted_reg_c2_res_slice3: exact;
    //     }
    //     actions = {
    //         drop_packet;
    //     }
    // }

    action resubmit_set(){
        ig_dprsr_md.resubmit_type = DPRSR_DIGEST_TYPE_A;
        md.a.f2 = mirror_tag;
    }

    action mirror_to_CPU(){
        md.ing_mir_ses = 10;
        ig_dprsr_md.mirror_type = 1;
        ig_tm_md.bypass_egress = 1w1;
        // clone_ingress_pkt_to_egress(md.ing_mir_ses)
    }

    action skip_egress(){
        ig_tm_md.bypass_egress = 1w1;
    }

    table resubmit_mirror_table{
        key = {
            overflow_flag: exact;
            ig_intr_md.resubmit_flag: exact;
        }
        actions = {
            resubmit_set;
            mirror_to_CPU;
            skip_egress;
        }
    } 

    action foward(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }

    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    table ipv4_port {
        key = { 
            ig_intr_md.ingress_port : exact; 
        }
        actions = {
            foward; 
            drop;
        }
        const entries = {
            44: foward(36);   // port 11 -> 12 (ens9np0 -> ens10np0)
            36: foward(44);   // port 12 -> 11 (ens10np0 -> ens9np0)
        }
        default_action = drop();
    }

    apply {
        set_global_time1_table.apply();
        global_time1_reg_set_table.apply();
        
        // global_time1 = ig_prsr_md.global_tstamp[33:33];  //about 8 seconds
        // global_time1 = ig_prsr_md.global_tstamp[35:35];  //about 32 seconds
		// global_time2 = ig_prsr_md.global_tstamp[33:33];  //about 8 seconds


        // Check packet type
        check_icmp_table.apply();   // ICMP flood
        check_udp_table.apply();    // UDP flood
        check_syn_table.apply();    // SYN flood
        check_dns_q_table.apply();  // DNS flood
        // Set toupdate to packet length for byte count
        // reg_c2_toupdate_value[15:0] = hdr.ipv4.total_len; // No coremelt detection in this version
        @stage(0){
        reg_c2_dyn_table.apply(); 
        reg_c2_key_a = hash0.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr});
        @stage(1){
            reg_c2_key_b = hash1.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr});
            reg_c2_key_0[15:0] = reg_c2_key_a[15:0];
            reg_c2_key_1[15:0] = reg_c2_key_a[31:16];
            reg_c2_key_2[15:0] = reg_c2_key_b[15:0];
			// set_flowkey5_table.apply(); 
        }
        // Check blocklist and if blocked set flag and set as drop
        check_blocklist.apply();

        //Update timer
        reg_c_timer1_table.apply(); 

        // Update register
        reg_c2_w1_0_table.apply();
        reg_c2_w1_1_table.apply();
        reg_c2_w1_2_table.apply();

        reg_c2_w2_0_table.apply();
        reg_c2_w2_1_table.apply();
        reg_c2_w2_2_table.apply();
        
        // Get merged result and apply slicing
        reg_c2_slicing_table.apply();

        @stage(1){
            // Get min data for in-data-plane filtering
            cms_stage_1.apply();
            cms_stage_2.apply();

            // check overflow
            reg_c2_overflow_table.apply();

            ipv4_port.apply();

            @stage(2){
                resubmit_mirror_table.apply();
            }
            // @stage(3){
            //     //skip egress pipeline
            //     ig_tm_md.bypass_egress = 1w1;
            // }
        }
        }
    }
}



control SwitchIngressDeparser(
        packet_out pkt,
        inout headers_t hdr,
        in metadata_t ig_md,
	  in ingress_intrinsic_metadata_for_deparser_t	ig_intr_dprsr_md) {
	Resubmit() resubmit;
    Mirror() mirror;
    apply {
		if (ig_intr_dprsr_md.resubmit_type == DPRSR_DIGEST_TYPE_A) {
			resubmit.emit(ig_md.a);
		}
        else if(ig_intr_dprsr_md.mirror_type == 1){
			mirror.emit<upload_h>(ig_md.ing_mir_ses, {ig_md.a.f2});
		}
        pkt.emit(hdr.upload);
		pkt.emit(hdr);
    }
}

/*****************************************
 ********     EGRESS PIPELINE     ********
 *****************************************/

// Egress Parser
parser SwitchEgressParser(
    packet_in pkt,
    /* User */
    out headers_t          hdr,
    out metadata_t         eg_md,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        upload_h upload_md;
		pkt.extract(upload_md);
		eg_md.upload_meta = upload_md.upload_type;
		transition parse_ethernet;
    }

    state parse_ethernet{
		pkt.extract(hdr.ethernet);
		transition select(hdr.ethernet.ether_type){
			0x800: parse_ipv4;
			default: reject;
		}
	}
    state parse_ipv4{
        pkt.extract(hdr.ipv4);
        transition accept;
    }
}

// Egress Match Action Pipeline
control SwitchEgress(
    /* User */
    inout headers_t         hdr,
    inout metadata_t        meta,
    /* Intrinsic */    
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    Register<bit<32>, bit<16>>(32w65536) reg_overflow_counter;
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_overflow_counter) reg_overflow_counter_update = {
        void apply(inout bit<32> value, out bit<32> read_value){
            value = value + 1;
            read_value = value; // Updated value
        }
    };

    bit<16> ctr_index = 0;

    action set_index(){
        ctr_index = eg_prsr_md.global_tstamp[42:27];
        reg_overflow_counter_update.execute(ctr_index);
    }

    table set_index_table {
        key = {
            hdr.ethernet.isValid(): exact;
        }
        actions = {
            set_index;
        }
    }

    apply {
        if(meta.upload_meta != 0) {
            hdr.ipv4.identification = meta.upload_meta;
            set_index_table.apply();
        }
    }
}

// Egress Deparser
control SwitchEgressDeparser(
    packet_out pkt,
    /* User */
    inout headers_t         hdr,
    in    metadata_t        meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    Checksum() ipv4_csum;
    apply {
        hdr.ipv4.hdr_checksum = ipv4_csum.update({
            hdr.ipv4.version, 
            hdr.ipv4.ihl, 
            hdr.ipv4.diffserv, 
            hdr.ipv4.total_len, 
            hdr.ipv4.identification, 
            hdr.ipv4.flags, 
            hdr.ipv4.frag_offset, 
            hdr.ipv4.ttl, 
            hdr.ipv4.protocol, 
            hdr.ipv4.src_addr, 
            hdr.ipv4.dst_addr 
        });
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
    }
}

/*****************************************
 ********      FINAL PACKAGE      ********
 *****************************************/
Pipeline(SwitchIngressParser(), 
    SwitchIngress(), 
    SwitchIngressDeparser(), 
    SwitchEgressParser(), 
    SwitchEgress(), 
    SwitchEgressDeparser()) pipe;

@pa_auto_init_metadata 
Switch( pipe ) main;