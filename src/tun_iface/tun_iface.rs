/*
Final package
MTU: 1472
UDP payload: 1444

For incapsulated tun iface = 1200
*/

use std::{
    io::{ErrorKind, IoSliceMut},
    net::Ipv4Addr,
    sync::{
        Arc, Weak,
        atomic::{AtomicU8, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use tun_rs::{DeviceBuilder, SyncDevice};

use crate::common::{loki_error::loki_error::LokiError, mpmc_queue::mpmc_queue::MpmcQueue};

pub struct TransmitItem {
    pub payload: Vec<u8>,
}

pub struct TunIfaceConfig {
    pub ipv4_addr: [u8; 4],
    pub enable_pi_ipv4_filter: bool,
    pub mtu: u16,
    pub mask: u8,
    pub destination_ipv4: Option<[u8; 4]>,
    pub device_name: String,
    pub recv_queue_cap: usize,
    pub send_queue_cap: usize,
}

pub struct TunIface {
    pub send_queue: Arc<MpmcQueue<TransmitItem>>,
    pub recv_queue: Arc<MpmcQueue<TransmitItem>>,
    stop_signals: Arc<AtomicU8>,
    background_queue_handle: JoinHandle<Result<(), LokiError>>,
}

impl TunIface {
    const MAX_MTU: usize = 1500;

    pub fn new_iface(iface_config: TunIfaceConfig) -> Result<Self, LokiError> {
        if iface_config.mtu > Self::MAX_MTU as u16 {
            return Err(LokiError::TunError(String::from(format!(
                "max mtu overflow mtu must be < {}",
                Self::MAX_MTU
            ))));
        }

        let dest_ipv4 = if let Some(d_ipv4) = iface_config.destination_ipv4 {
            Some(Ipv4Addr::from_octets(d_ipv4))
        } else {
            None
        };

        let d = DeviceBuilder::new()
            .name(iface_config.device_name)
            .layer(tun_rs::Layer::L3) //TUN
            .mtu(iface_config.mtu)
            .packet_information(iface_config.enable_pi_ipv4_filter)
            .ipv4(
                Ipv4Addr::from_octets(iface_config.ipv4_addr),
                iface_config.mask,
                dest_ipv4,
            )
            .build_sync();

        if d.is_err() {
            return Err(LokiError::TunError(d.err().unwrap().to_string()));
        }

        let send_queue = Arc::new(MpmcQueue::with_capacity(iface_config.send_queue_cap));
        let recv_queue = Arc::new(MpmcQueue::with_capacity(iface_config.recv_queue_cap));

        let send_queue_weak = Arc::downgrade(&send_queue);
        let recv_queue_weak = Arc::downgrade(&recv_queue);

        let device = d.unwrap();

        if let Some(err) = device.set_nonblocking(true).err() {
            return Err(LokiError::TunError(err.to_string()));
        }
        let enable_pi_ipv4_filter = iface_config.enable_pi_ipv4_filter;
        let stop_signals = Arc::new(AtomicU8::new(0));
        let stop_signals_weak = Arc::downgrade(&stop_signals);
        let background_queue_handle = thread::spawn(move || {
            Self::background_loop(
                send_queue_weak,
                recv_queue_weak,
                device,
                stop_signals_weak,
                enable_pi_ipv4_filter,
            )
        });

        Ok(Self {
            recv_queue: recv_queue,
            send_queue: send_queue,
            stop_signals: stop_signals,
            background_queue_handle,
        })
    }

    pub fn shutdown(self) -> Result<(), LokiError> {
        self.stop_signals.fetch_add(1, Ordering::AcqRel);
        match self.background_queue_handle.join() {
            Ok(res) => res,
            Err(_) => {
                return Err(LokiError::TunError(String::from(
                    "join background queue failed",
                )));
            }
        }
    }

    pub fn is_running(&self) -> bool {
        self.stop_signals.load(Ordering::Acquire) == 0
    }

    pub fn send(&self, i: TransmitItem) -> Result<Result<(), TransmitItem>, LokiError> {
        if self.is_running() {
            Ok(self.send_queue.push(i))
        } else {
            Err(LokiError::TunError(String::from("broken pipe")))
        }
    }

    pub fn send_blocking(&self, i: TransmitItem) -> Result<(), LokiError> {
        if self.is_running() {
            Ok(self.send_queue.push_blocking(i))
        } else {
            Err(LokiError::TunError(String::from("broken pipe")))
        }
    }

    pub fn receive(&self) -> Result<Option<TransmitItem>, LokiError> {
        if self.is_running() {
            Ok(self.recv_queue.pop())
        } else {
            Err(LokiError::TunError(String::from("broken pipe")))
        }
    }

    pub fn has_received_items(&self) -> bool {
        return !self.recv_queue.is_empty();
    }

    pub fn can_send_item(&self) -> bool {
        return !self.send_queue.is_full();
    }

    fn send_with_would_block_processing(
        dev: &SyncDevice,
        buff: &Vec<u8>,
    ) -> Result<bool, LokiError> {
        match dev.send(&buff) {
            Ok(_) => {
                return Ok(true);
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                return Ok(false);
            }
            Err(e) => {
                return Err(LokiError::TunError(String::from(format!(
                    "send fail info: {}",
                    e.to_string()
                ))));
            }
        }
    }

    fn background_loop(
        send: Weak<MpmcQueue<TransmitItem>>,
        recv: Weak<MpmcQueue<TransmitItem>>,
        device: SyncDevice,
        stop_signals: Weak<AtomicU8>,
        enable_pi_ipv4_filter: bool,
    ) -> Result<(), LokiError> {
        let Some(stop_signals) = stop_signals.upgrade() else {
            return Err(LokiError::TunError(String::from(
                "background_loop can't upgrade stop signals",
            )));
        };

        let mut err: Option<LokiError> = None;

        loop {
            //if not zero - continue
            if stop_signals.load(Ordering::Acquire) > 0 {
                //receive stop signal
                break;
            }

            let Some(send) = send.upgrade() else {
                err = Some(LokiError::TunError(String::from(
                    "background_loop can't upgrade send queue",
                )));
                break;
            };

            let Some(recv) = recv.upgrade() else {
                err = Some(LokiError::TunError(String::from(
                    "background_loop can't upgrade recv queue",
                )));
                break;
            };

            let mut some_received = false;

            if !recv.is_full() {
                let mut raw_buff = [0u8; Self::MAX_MTU];
                let buff = IoSliceMut::new(&mut raw_buff);
                let mut buffs = [buff];
                match device.recv_vectored(&mut buffs) {
                    Ok(len) if len > 0 => {
                        let mut payload = Vec::new();
                        payload.reserve(len);

                        if enable_pi_ipv4_filter {
                            let pi = &raw_buff[..4];

                            let proto_raw = &pi[2..4];

                            let mut proto_u16 = 0u16;
                            proto_u16 |= proto_raw[1] as u16;
                            proto_u16 |= (proto_raw[0] as u16) << 8;

                            if proto_u16 == 0x0800 {
                                payload.extend_from_slice(&raw_buff[4..len]);
                                some_received = true;
                                recv.push_blocking(TransmitItem { payload: payload });
                            } else {
                                //tun has packet -> has activity -> no yield
                                some_received = true;
                            }
                        } else {
                            payload.extend_from_slice(&raw_buff[..len]);

                            some_received = true;
                            recv.push_blocking(TransmitItem { payload: payload });
                        }
                    }
                    Ok(_) => {}
                    Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                        //no error no data
                    }
                    Err(e) => {
                        err = Some(LokiError::TunError(String::from(format!(
                            "recv_vectored fail info: {}",
                            e.to_string()
                        ))));
                        break;
                    }
                }
            }
            let mut some_sended = false;
            let mut send_dropped = false;
            if !send.is_empty() {
                if let Some(val) = send.pop() {
                    match Self::send_with_would_block_processing(&device, &val.payload) {
                        Ok(send_ok) => {
                            some_sended = send_ok;
                            send_dropped = !send_ok;
                        }
                        Err(e) => {
                            err = Some(e);
                            break;
                        }
                    }
                }
            }

            if send_dropped && send.is_full() {
                //drop next oldest package lowed pressure
                _ = send.pop()
                //todo add trotting detection and advanced scheme for resolving situation
            }

            if !some_received && !some_sended {
                std::thread::sleep(Duration::from_micros(100));
            }
        }

        if err.is_none() {
            Ok(())
        } else {
            Err(err.unwrap())
        }
    }
}
