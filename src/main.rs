use crate::{
    cli::cli::{Cli, CliConfig, CliTransmitItem},
    common::loki_error::loki_error::LokiError,
    srv::srv::{Srv, SrvConfig, SrvTransmitItem},
    tun_iface::tun_iface::{TransmitItem, TunIface, TunIfaceConfig},
    xorer::xorer::Xorer,
};

use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
    ops::Deref,
    str::FromStr,
    sync::{Arc, Mutex, Weak, atomic::AtomicBool},
    thread,
    time::Duration,
};

/*
MTU tun ≤ 1350

UDP payload ≤ 1400

лучше не превышать 1380
*/

use signal_hook::{consts::SIGTERM, iterator::Signals};
use std::error::Error;

use dashmap::DashMap;
use thread::{JoinHandle, Thread};

mod cli;
mod common;
mod srv;
mod tun_iface;
mod xorer;

use clap::{Command, Parser, builder::Str};

#[derive(Parser, Debug)]
#[command(author, version, about)]

/*

server
./loki

client
./loki -c --target_net wlp229s0 --server_addr 1.1.1.1



*/
struct Args {
    #[arg(short, long, default_value_t = false)]
    client: bool,

    #[arg(long, default_value_t = String::from("eno1"))]
    target_net: String,

    #[arg(long, default_value_t = String::from("192.168.0.2"))]
    vpn_ip: String,

    #[arg(long, default_value_t = String::from("192.168.0.1"))]
    vpn_gate: String,

    #[arg(long, default_value_t = String::from(""))]
    target_net_addr: String,

    #[arg(long, default_value_t = String::from(""))]
    server_addr: String,
}

fn restore_default_route(saved: &str) -> Result<(), LokiError> {
    let _ = std::process::Command::new("ip")
        .args(["route", "del", "default"])
        .status();

    let mut cmd = std::process::Command::new("ip");
    cmd.args(["route", "add"]);
    cmd.args(saved.split_whitespace());

    let status = cmd
        .status()
        .map_err(|e| LokiError::MainError(e.to_string()))?;

    if !status.success() {
        return Err(LokiError::MainError(
            "failed to restore default route".into(),
        ));
    }

    Ok(())
}

fn get_default_route() -> Result<String, LokiError> {
    let out = std::process::Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .map_err(|e| LokiError::MainError(e.to_string()))?;

    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn parse_ipv4_src_dst(packet: &Vec<u8>) -> Option<([u8; 4], [u8; 4])> {
    if packet.len() < 20 {
        return None;
    }

    let ihl = (packet[0] & 0x0f) as usize * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }

    let version = packet[0] >> 4;
    if version != 4 {
        return None;
    }

    let src = [packet[12], packet[13], packet[14], packet[15]];
    let dst = [packet[16], packet[17], packet[18], packet[19]];

    Some((src, dst))
}

fn ensure_iptables_rule(
    table: Option<&str>,
    chain: &str,
    rule: &[&str],
    insert: bool,
) -> Result<(), LokiError> {
    let mut check = std::process::Command::new("iptables");
    if let Some(t) = table {
        check.args(["-t", t]);
    }
    check.arg("-C").arg(chain).args(rule);

    let exists = check.status().map(|s| s.success()).unwrap_or(false);

    if !exists {
        let mut cmd = std::process::Command::new("iptables");
        if let Some(t) = table {
            cmd.args(["-t", t]);
        }

        if insert {
            cmd.arg("-I").arg(chain);
        } else {
            cmd.arg("-A").arg(chain);
        }

        cmd.args(rule);

        let status = cmd
            .status()
            .map_err(|e| LokiError::MainError(format!("iptables failed: {}", e)))?;

        if !status.success() {
            return Err(LokiError::MainError(format!(
                "iptables rule insert failed: {:?}",
                rule
            )));
        }
    }

    Ok(())
}

fn main() {
    let args = Args::parse();
    if !args.client {
        let res = start_server(args.target_net);
        if res.is_err() {
            println!("Server stopped err {}", res.err().unwrap())
        } else {
            println!("Server stopped without err")
        }
    } else {
        if args.server_addr.is_empty() {
            println!("add --server-addr <ip>. exit from app");
            return;
        }

        if args.target_net_addr.is_empty() {
            println!("add --target-net-addr <ip>. exit from app");
            return;
        }

        let server_addr: Ipv4Addr;
        match Ipv4Addr::from_str(&args.server_addr) {
            Ok(addr) => server_addr = addr,
            Err(_) => {
                println!("--server_addr parse err");
                return;
            }
        }
        let vpn_ip_addr: Ipv4Addr;
        match Ipv4Addr::from_str(&args.vpn_ip) {
            Ok(addr) => vpn_ip_addr = addr,
            Err(_) => {
                println!("--vpn_ip parse err");
                return;
            }
        }

        let vpn_gate_addr: Ipv4Addr;
        match Ipv4Addr::from_str(&args.vpn_gate) {
            Ok(addr) => vpn_gate_addr = addr,
            Err(_) => {
                println!("--vpn_gate parse err");
                return;
            }
        }

        let default_route = get_default_route();
        let Some(default_route) = default_route.ok() else {
            println!("can't make route backup");
            return;
        };

        let srv_addr_octets = server_addr.octets();
        let vpn_ip_addr_octets = vpn_ip_addr.octets();
        let vpn_gate_addr_octets = vpn_gate_addr.octets();
        match start_client(
            args.target_net,
            [
                srv_addr_octets[0],
                srv_addr_octets[1],
                srv_addr_octets[2],
                srv_addr_octets[3],
            ],
            [
                vpn_ip_addr_octets[0],
                vpn_ip_addr_octets[1],
                vpn_ip_addr_octets[2],
                vpn_ip_addr_octets[3],
            ],
            [
                vpn_gate_addr_octets[0],
                vpn_gate_addr_octets[1],
                vpn_gate_addr_octets[2],
                vpn_gate_addr_octets[3],
            ],
            args.target_net_addr,
        ) {
            Ok(_) => println!("Client stopped"),
            Err(e) => println!("Client stopped err {}", e),
        }

        match restore_default_route(&default_route) {
            Ok(_) => println!("Route restored"),
            Err(_) => println!(
                "Warn !!! Fail restored route backup: \n{}\nPress any key to exit...",
                default_route
            ),
        }
    }
}

fn start_client(
    target_iface: String,
    server_addr: [u8; 4],
    vpn_ip: [u8; 4],
    vpn_gate: [u8; 4],
    target_net_addr: String,
) -> Result<(), LokiError> {
    let Some(mut signals) = Signals::new(&[SIGTERM]).ok() else {
        return Err(LokiError::MainError(String::from(
            "can't create SIGTERM handler",
        )));
    };

    let tun_config = TunIfaceConfig {
        ipv4_addr: vpn_ip,
        mtu: 1472,
        mask: 32,
        destination_ipv4: Some(vpn_gate),
        device_name: String::from("loki0"),
        enable_pi_ipv4_filter: false,
        recv_queue_cap: 128,
        send_queue_cap: 128,
    };

    let tun = Arc::new(TunIface::new_iface(tun_config)?);

    //ip_tables
    ensure_iptables_rule(None, "OUTPUT", &["-o", "loki0", "-j", "ACCEPT"], true)?;
    ensure_iptables_rule(
        None,
        "INPUT",
        &[
            "-i",
            "loki0",
            "-m",
            "conntrack",
            "--ctstate",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ],
        true,
    )?;
    ensure_iptables_rule(None, "INPUT", &["-i", "loki0", "-j", "ACCEPT"], true)?;

    //routes

    if !std::process::Command::new("ip")
        .arg("route")
        .arg("add")
        .arg("default")
        .arg("dev")
        .arg("loki0")
        .arg("via")
        .arg("192.168.0.1")
        .status()
        .map_err(|e| LokiError::MainError(e.to_string()))?
        .success()
    {
        return Err(LokiError::MainError(
            "failed to change default route".into(),
        ));
    }

    if !std::process::Command::new("ip")
        .arg("route")
        .arg("add")
        .arg(format!(
            "{}.{}.{}.{}/32",
            server_addr[0], server_addr[1], server_addr[2], server_addr[3]
        ))
        .arg("via")
        .arg(&target_net_addr)
        .status()
        .map_err(|e| LokiError::MainError(e.to_string()))?
        .success()
    {
        println!("WARN failed to add unique server route")
    }

    let udp_client_config = CliConfig {
        ipv4_host: server_addr,
        ipv4_port: 51820,
        recv_queue_cap: 128,
        send_queue_cap: 128,
        mtu: 1472,
    };

    let udp_cli = Arc::new(Cli::new(udp_client_config)?);

    let tun_weak_a = Arc::downgrade(&tun);
    let udp_cli_weak_a = Arc::downgrade(&udp_cli);

    let udp_cli_to_tun_handle =
        thread::spawn(move || cli_udp_to_tun_pipe(udp_cli_weak_a, tun_weak_a));

    let tun_weak_b = Arc::downgrade(&tun);
    let udp_cli_weak_b = Arc::downgrade(&udp_cli);

    let tun_to_udp_cli_handle =
        thread::spawn(move || cli_tun_to_udp_pipe(udp_cli_weak_b, tun_weak_b));

    //watch dog

    println!("Client started");

    let sigterm_received = Arc::new(AtomicBool::new(false));
    let sigterm_received_weak = Arc::downgrade(&sigterm_received);
    thread::spawn(move || {
        for sig in signals.forever() {
            if sig == SIGTERM {
                let Some(sigterm_received_weak) = sigterm_received_weak.upgrade() else {
                    return;
                };
                sigterm_received_weak.store(true, std::sync::atomic::Ordering::Release);
            }
        }
    });

    while (tun.is_running() && udp_cli.is_running())
        && !sigterm_received.load(std::sync::atomic::Ordering::Relaxed)
    {
        eprint!(
            "\r Tun Rx/Tx: {}/{}, Udp Rx/Tx: {}/{}",
            tun.recv_queue.len(),
            tun.send_queue.len(),
            udp_cli.recv_queue.len(),
            udp_cli.send_queue.len()
        );
        std::io::Write::flush(&mut std::io::stderr()).unwrap();
        std::thread::sleep(Duration::from_millis(500));
    }

    if let Some(tun_moved) = Arc::try_unwrap(tun).ok() {
        let tun_shutdown_res = tun_moved.shutdown();
        if tun_shutdown_res.is_err() {
            println!("tun_shutdown err: {}", tun_shutdown_res.err().unwrap());
        }
    }
    if let Some(cli_moved) = Arc::try_unwrap(udp_cli).ok() {
        let cli_shutdown_res = cli_moved.shutdown();
        if cli_shutdown_res.is_err() {
            println!("cli_shutdown err: {}", cli_shutdown_res.err().unwrap());
        }
    }

    let tun_to_cli_join_res = tun_to_udp_cli_handle.join();
    if tun_to_cli_join_res.is_err() {
        println!("tun_to_cli_join err: thread join err",);
    } else {
        let ok = tun_to_cli_join_res.ok().unwrap();
        if ok.is_err() {
            println!("tun_to_cli_join err: {}", ok.err().unwrap());
        }
    }

    let cli_to_tun_join_res = udp_cli_to_tun_handle.join();
    if cli_to_tun_join_res.is_err() {
        println!("tun_to_cli_join err: thread join err",);
    } else {
        let ok = cli_to_tun_join_res.ok().unwrap();
        if ok.is_err() {
            println!("tun_to_cli_join err: {}", ok.err().unwrap());
        }
    }

    Ok(())
}

fn start_server(target_iface: String) -> Result<(), LokiError> {
    let Some(mut signals) = Signals::new(&[SIGTERM]).ok() else {
        return Err(LokiError::MainError(String::from(
            "can't create SIGTERM handler",
        )));
    };
    //addr map - key is tun addr, val is udp addr
    let addr_map: Arc<DashMap<u32, SocketAddr>> = Arc::new(DashMap::new());

    let tun_config = TunIfaceConfig {
        ipv4_addr: [192, 168, 0, 1],
        enable_pi_ipv4_filter: false,
        mtu: 1472,
        mask: 16,
        destination_ipv4: None,
        device_name: String::from("loki0"),
        recv_queue_cap: 128,
        send_queue_cap: 128,
    };

    let srv_config = SrvConfig {
        ipv4_listen_host: [0, 0, 0, 0],
        ipv4_listen_port: 51820,
        recv_queue_cap: 128,
        send_queue_cap: 128,
        mtu: 1472,
    };

    let tun = Arc::new(TunIface::new_iface(tun_config)?);
    let srv = Arc::new(Srv::new(srv_config)?);

    let tun_weak_a = Arc::downgrade(&tun);
    let srv_weak_a = Arc::downgrade(&srv);
    let addr_map_weak_a = Arc::downgrade(&addr_map);

    //server -> tun (client tun use src)

    let srv_to_tun_handle =
        thread::spawn(move || udp_to_tun_pipe(srv_weak_a, tun_weak_a, addr_map_weak_a));

    let tun_weak_b = Arc::downgrade(&tun);
    let srv_weak_b = Arc::downgrade(&srv);
    let addr_map_weak_b = Arc::downgrade(&addr_map);

    //tun->server (server tun use dst)

    let tun_to_srv_handle =
        thread::spawn(move || tun_to_udp_pipe(srv_weak_b, tun_weak_b, addr_map_weak_b));

    //ip tables

    ensure_iptables_rule(
        None,
        "FORWARD",
        &["-i", "loki0", "-o", &target_iface, "-j", "ACCEPT"],
        true,
    )?;

    ensure_iptables_rule(
        None,
        "FORWARD",
        &[
            "-i",
            &target_iface,
            "-o",
            "loki0",
            "-m",
            "conntrack",
            "--ctstate",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ],
        true,
    )?;

    ensure_iptables_rule(
        Some("nat"),
        "POSTROUTING",
        &[
            "-s",
            "192.168.0.0/16",
            "-o",
            &target_iface,
            "-j",
            "MASQUERADE",
        ],
        false,
    )?;

    //watch dog
    println!("Server started");
    let sigterm_received = Arc::new(AtomicBool::new(false));
    let sigterm_received_weak = Arc::downgrade(&sigterm_received);
    thread::spawn(move || {
        for sig in signals.forever() {
            if sig == SIGTERM {
                let Some(sigterm_received_weak) = sigterm_received_weak.upgrade() else {
                    return;
                };
                sigterm_received_weak.store(true, std::sync::atomic::Ordering::Release);
            }
        }
    });

    while (tun.is_running() && srv.is_running())
        && !sigterm_received.load(std::sync::atomic::Ordering::Relaxed)
    {
        std::thread::sleep(Duration::from_secs(1));
    }

    if let Some(tun_moved) = Arc::try_unwrap(tun).ok() {
        let tun_shutdown_res = tun_moved.shutdown();
        if tun_shutdown_res.is_err() {
            println!("tun_shutdown err: {}", tun_shutdown_res.err().unwrap());
        }
    }
    if let Some(srv_moved) = Arc::try_unwrap(srv).ok() {
        let srv_shutdown_res = srv_moved.shutdown();
        if srv_shutdown_res.is_err() {
            println!("srv_shutdown err: {}", srv_shutdown_res.err().unwrap());
        }
    }

    let tun_to_srv_join_res = tun_to_srv_handle.join();
    if tun_to_srv_join_res.is_err() {
        println!("tun_to_srv_join err: thread join err",);
    } else {
        let ok = tun_to_srv_join_res.ok().unwrap();
        if ok.is_err() {
            println!("tun_to_srv_join err: {}", ok.err().unwrap());
        }
    }

    let srv_to_tun_join_res = srv_to_tun_handle.join();
    if srv_to_tun_join_res.is_err() {
        println!("tun_to_srv_join err: thread join err",);
    } else {
        let ok = srv_to_tun_join_res.ok().unwrap();
        if ok.is_err() {
            println!("tun_to_srv_join err: {}", ok.err().unwrap());
        }
    }

    Ok(())
}

fn cli_tun_to_udp_pipe(cli: Weak<Cli>, tun: Weak<TunIface>) -> Result<(), LokiError> {
    loop {
        let Some(tun) = tun.upgrade() else {
            return Err(LokiError::MainError(String::from(
                "cli tun -> server can't upgrade tun",
            )));
        };
        if !tun.is_running() {
            println!("ERR cli tun -> server: tun device not started or stopped");
            break;
        }
        let Some(cli) = cli.upgrade() else {
            return Err(LokiError::MainError(String::from(
                "cli tun -> server can't upgrade cli",
            )));
        };

        if tun.has_received_items() && cli.can_send_item() {
            let tun_received_item: Option<TransmitItem>;
            match tun.receive() {
                Ok(val) => tun_received_item = val,
                Err(err) => {
                    return Err(LokiError::MainError(String::from(format!(
                        "ERR cli tun -> server: {}",
                        err
                    ))));
                }
            }

            let Some(tun_received_item) = tun_received_item else {
                println!("WARN tun -> server: no packet! maybe UB? but not critical");
                std::thread::sleep(Duration::from_millis(2));
                continue;
            };

            let mut payload = tun_received_item.payload;
            let err = Xorer::xor(&mut payload);
            if err.is_some() {
                return Err(err.unwrap());
            }

            match cli.send(CliTransmitItem { payload: payload }) {
                Ok(res) => {
                    if res.err().is_some() {
                        println!("WARN tun -> server: super trottling drop new package");
                    }
                }
                Err(err) => {
                    return Err(LokiError::MainError(String::from(format!(
                        "ERR tun -> server: {}",
                        err
                    ))));
                }
            }
        } else {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    Ok(())
}

fn tun_to_udp_pipe(
    srv: Weak<Srv>,
    tun: Weak<TunIface>,
    addr_map: Weak<DashMap<u32, SocketAddr>>,
) -> Result<(), LokiError> {
    loop {
        let Some(tun) = tun.upgrade() else {
            return Err(LokiError::MainError(String::from(
                "tun -> server can't upgrade addr_map",
            )));
        };
        if !tun.is_running() {
            println!("ERR tun -> server: tun device not started or stopped");
            break;
        }
        let Some(srv) = srv.upgrade() else {
            return Err(LokiError::MainError(String::from(
                "tun -> server can't upgrade srv",
            )));
        };
        if tun.has_received_items() && srv.can_send_item() {
            let tun_received_item: Option<TransmitItem>;
            match tun.receive() {
                Ok(val) => tun_received_item = val,
                Err(err) => {
                    return Err(LokiError::MainError(String::from(format!(
                        "ERR tun -> server: {}",
                        err
                    ))));
                }
            }

            let Some(tun_received_item) = tun_received_item else {
                println!("WARN tun -> server: no packet! maybe UB? but not critical");
                std::thread::sleep(Duration::from_millis(2));
                continue;
            };

            let ipv4_src_dst = parse_ipv4_src_dst(&tun_received_item.payload);
            let Some(ipv4_src_dst) = ipv4_src_dst else {
                println!("WARN tun -> server: can't parse src/dst ipv4 section drop");
                continue;
            };

            let ipv4_dst = ipv4_src_dst.1;
            let ipv4_dst_u32: u32 = u32::from_be_bytes(ipv4_dst);
            let Some(addr_map) = addr_map.upgrade() else {
                return Err(LokiError::MainError(String::from(
                    "tun -> server can't upgrade addr_map",
                )));
            };
            if addr_map.contains_key(&ipv4_dst_u32) {
                let addr = addr_map.get(&ipv4_dst_u32).unwrap().clone();

                let mut payload = tun_received_item.payload;
                let err = Xorer::xor(&mut payload);
                if err.is_some() {
                    return Err(err.unwrap());
                }

                match srv.send(SrvTransmitItem {
                    addr,
                    payload: payload,
                }) {
                    Ok(res) => {
                        if res.err().is_some() {
                            println!("WARN tun -> server: super trottling drop new package");
                        }
                    }
                    Err(err) => {
                        return Err(LokiError::MainError(String::from(format!(
                            "ERR tun -> server: {}",
                            err
                        ))));
                    }
                }
            } else {
                println!("WARN tun -> server: can't find target udp client - drop");
                continue;
            }
        } else {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    Ok(())
}

fn cli_udp_to_tun_pipe(cli: Weak<Cli>, tun: Weak<TunIface>) -> Result<(), LokiError> {
    loop {
        let Some(cli) = cli.upgrade() else {
            return Err(LokiError::MainError(String::from(
                "cli -> tun can't upgrade cli",
            )));
        };
        if !cli.is_running() {
            println!("ERR  cli -> tun: Server not started or stopped");
            break;
        }

        let Some(tun) = tun.upgrade() else {
            return Err(LokiError::MainError(String::from(
                "cli -> tun can't upgrade addr_map",
            )));
        };
        if cli.has_received_items() && tun.can_send_item() {
            let udp_received_item: Option<CliTransmitItem>;
            match cli.receive() {
                Ok(val) => udp_received_item = val,
                Err(err) => {
                    return Err(LokiError::MainError(String::from(format!(
                        "ERR server -> tun: {}",
                        err
                    ))));
                }
            }
            let Some(udp_received_item) = udp_received_item else {
                println!("WARN cli -> tun: no packet! maybe UB? but not critical");
                std::thread::sleep(Duration::from_millis(2));
                continue;
            };

            let mut udp_payload = udp_received_item.payload;
            let err = Xorer::un_xor_verify(&mut udp_payload);
            if err.is_some() {
                match err {
                    Some(lerr) if lerr == LokiError::XORIpv4VerifyFail => {
                        println!("bad package - drop");
                        continue;
                    }
                    Some(e) => return Err(e),
                    None => {}
                }
            }

            match tun.send(TransmitItem {
                payload: udp_payload,
            }) {
                Ok(res) => {
                    if res.err().is_some() {
                        println!("WARN server -> tun: super trottling drop new package");
                    }
                }
                Err(err) => {
                    return Err(LokiError::MainError(String::from(format!(
                        "ERR server -> tun: {}",
                        err
                    ))));
                }
            }
        } else {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    Ok(())
}

fn udp_to_tun_pipe(
    srv: Weak<Srv>,
    tun: Weak<TunIface>,
    addr_map: Weak<DashMap<u32, SocketAddr>>,
) -> Result<(), LokiError> {
    loop {
        let Some(srv) = srv.upgrade() else {
            return Err(LokiError::MainError(String::from(
                "server -> tun can't upgrade srv",
            )));
        };
        if !srv.is_running() {
            println!("ERR server -> tun: Server not started or stopped");
            break;
        }
        let Some(tun) = tun.upgrade() else {
            return Err(LokiError::MainError(String::from(
                "server -> tun can't upgrade addr_map",
            )));
        };
        if srv.has_received_items() && tun.can_send_item() {
            let udp_received_item: Option<SrvTransmitItem>;
            match srv.receive() {
                Ok(val) => udp_received_item = val,
                Err(err) => {
                    return Err(LokiError::MainError(String::from(format!(
                        "ERR server -> tun: {}",
                        err
                    ))));
                }
            }
            let Some(udp_received_item) = udp_received_item else {
                println!("WARN server -> tun: no packet! maybe UB? but not critical");
                std::thread::sleep(Duration::from_millis(2));
                continue;
            };

            let mut udp_payload = udp_received_item.payload;
            let err = Xorer::un_xor_verify(&mut udp_payload);
            if err.is_some() {
                match err {
                    Some(lerr) if lerr == LokiError::XORIpv4VerifyFail => {
                        println!("bad package - drop");
                        continue;
                    }
                    Some(e) => return Err(e),
                    None => {}
                }
            }

            let ipv4_src_dst = parse_ipv4_src_dst(&udp_payload);
            let Some(ipv4_src_dst) = ipv4_src_dst else {
                println!("WARN server -> tun: can't parse src/dst ipv4 section drop");
                continue;
            };

            let ipv4_src = ipv4_src_dst.0;
            let udp_addr = udp_received_item.addr;

            let ipv4_src_u32: u32 = u32::from_be_bytes(ipv4_src);
            let Some(addr_map) = addr_map.upgrade() else {
                return Err(LokiError::MainError(String::from(
                    "server -> tun can't upgrade addr_map",
                )));
            };
            if addr_map.contains_key(&ipv4_src_u32) {
                if !(*addr_map.get(&ipv4_src_u32).unwrap()).eq(&udp_addr) {
                    *addr_map.get_mut(&ipv4_src_u32).unwrap() = udp_addr
                }
            } else {
                addr_map.insert(ipv4_src_u32, udp_addr);
            }

            match tun.send(TransmitItem {
                payload: udp_payload,
            }) {
                Ok(res) => {
                    if res.err().is_some() {
                        println!("WARN server -> tun: super trottling drop new package");
                    }
                }
                Err(err) => {
                    return Err(LokiError::MainError(String::from(format!(
                        "ERR server -> tun: {}",
                        err
                    ))));
                }
            }
        } else {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    Ok(())
}

//route - default via 192.168.0.1 dev loki0
