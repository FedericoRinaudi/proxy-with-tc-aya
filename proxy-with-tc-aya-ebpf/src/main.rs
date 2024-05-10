#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{
        TC_ACT_OK,
        bpf_adj_room_mode::BPF_ADJ_ROOM_NET
    },
    macros::{classifier},
    programs::TcContext,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    tcp::TcpHdr,
};

const PROXY_IP: u32 = 0xc0a83805;
const PADDING_LEN: i32 = -32;

#[classifier]
pub fn proxy_with_tc_aya(ctx: TcContext) -> i32 {
    match try_proxy_with_tc_aya(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_proxy_with_tc_aya(mut ctx: TcContext) -> Result<i32, i32> {
    let eth_hdr: EthHdr = ctx.load(0).map_err(|_| TC_ACT_OK)?;
    match eth_hdr.ether_type {
        EtherType::Ipv4 => {}
        _ => return Ok(TC_ACT_OK),
    }

    let ipv4_hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| TC_ACT_OK)?;
    let source = u32::from_be(ipv4_hdr.src_addr);

    let action = TC_ACT_OK;

    if source != PROXY_IP {
        info!(&ctx, "NON PROXY_IP: {:x}", source);
        return Ok(TC_ACT_OK);
    }

    info!(&ctx, "DEST {:i}, ACTION {}", source, action);

    if ipv4_hdr.proto != IpProto::Tcp.into() {
        info!(&ctx, "NON TCP");
        return Ok(TC_ACT_OK);
    }

    let ipv4_len: usize =  (ipv4_hdr.ihl() << 2).into();
    let tcp_offset = EthHdr::LEN + ipv4_len;
    let tcp_hdr: TcpHdr = ctx.load(tcp_offset).map_err(|_| TC_ACT_OK)?;
    let tcp_len: usize = (tcp_hdr.doff() << 2).into();
    let http_end = tcp_offset + tcp_len;

    if ctx.len() <= http_end as u32 {
        info!(&ctx, "NO HTTP");
        return Ok(TC_ACT_OK);
    }

    info!(&ctx, "HTTP");

    ctx.adjust_room(PADDING_LEN, BPF_ADJ_ROOM_NET, 0).map_err(|_| TC_ACT_OK)?;
    ctx.store(tcp_offset, &tcp_hdr, 0).map_err(|_| TC_ACT_OK)?;


    Ok(TC_ACT_OK)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
