use std::{
    io::ErrorKind,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
    sync::{
        Arc, Weak,
        atomic::{AtomicU8, Ordering},
    },
    thread::{self, JoinHandle, Thread},
    time::Duration,
};

use crate::common::{loki_error::loki_error::LokiError, mpmc_queue::mpmc_queue::MpmcQueue};

pub struct SrvConfig {
    pub ipv4_listen_host: [u8; 4],
    pub ipv4_listen_port: u16,
    pub recv_queue_cap: usize,
    pub send_queue_cap: usize,
    pub mtu: u16,
}

pub struct SrvTransmitItem {
    pub addr: SocketAddr,
    pub payload: Vec<u8>,
}

pub struct Srv {
    send_queue: Arc<MpmcQueue<SrvTransmitItem>>,
    recv_queue: Arc<MpmcQueue<SrvTransmitItem>>,
    stop_signals: Arc<AtomicU8>,

    background_queue_handle: JoinHandle<Result<(), LokiError>>,
}

impl Srv {
    const MAX_MTU: usize = 1500;

    pub fn new(cfg: SrvConfig) -> Result<Self, LokiError> {
        let device: UdpSocket;

        if cfg.mtu > Self::MAX_MTU as u16 {
            return Err(LokiError::SrvError(String::from(format!(
                "max mtu overflow mtu must be < {}",
                Self::MAX_MTU
            ))));
        }

        match UdpSocket::bind(SocketAddrV4::new(
            Ipv4Addr::from_octets(cfg.ipv4_listen_host),
            cfg.ipv4_listen_port,
        )) {
            Ok(dev) => device = dev,
            Err(err) => return Err(LokiError::SrvError(err.to_string())),
        }

        let send_queue = Arc::new(MpmcQueue::with_capacity(cfg.send_queue_cap));
        let recv_queue = Arc::new(MpmcQueue::with_capacity(cfg.recv_queue_cap));

        let send_queue_weak = Arc::downgrade(&send_queue);
        let recv_queue_weak = Arc::downgrade(&recv_queue);

        if let Some(err) = device.set_nonblocking(true).err() {
            return Err(LokiError::SrvError(err.to_string()));
        }

        let stop_signals = Arc::new(AtomicU8::new(0));
        let stop_signals_weak = Arc::downgrade(&stop_signals);

        let background_queue_handle = thread::spawn(move || {
            Self::background_loop(send_queue_weak, recv_queue_weak, device, stop_signals_weak)
        });

        Ok(Self {
            send_queue,
            recv_queue,
            stop_signals,
            background_queue_handle,
        })
    }

    pub fn shutdown(self) -> Result<(), LokiError> {
        self.stop_signals.fetch_add(1, Ordering::AcqRel);
        match self.background_queue_handle.join() {
            Ok(res) => res,
            Err(_) => {
                return Err(LokiError::SrvError(String::from(
                    "join background queue failed",
                )));
            }
        }
    }

    pub fn is_running(&self) -> bool {
        self.stop_signals.load(Ordering::Acquire) == 0
    }

    pub fn send(&self, i: SrvTransmitItem) -> Result<Result<(), SrvTransmitItem>, LokiError> {
        if self.is_running() {
            Ok(self.send_queue.push(i))
        } else {
            Err(LokiError::SrvError(String::from("broken pipe")))
        }
    }

    pub fn receive(&self) -> Result<Option<SrvTransmitItem>, LokiError> {
        if self.is_running() {
            Ok(self.recv_queue.pop())
        } else {
            Err(LokiError::SrvError(String::from("broken pipe")))
        }
    }

    pub fn has_received_items(&self) -> bool {
        return !self.recv_queue.is_empty();
    }

    pub fn can_send_item(&self) -> bool {
        return !self.send_queue.is_full();
    }

    fn send_with_would_block_processing(
        dev: &UdpSocket,
        buff: &Vec<u8>,
        addr: &SocketAddr,
    ) -> Result<bool, LokiError> {
        match dev.send_to(&buff, addr) {
            Ok(_) => {
                return Ok(true);
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                return Ok(false);
            }
            Err(e) => {
                return Err(LokiError::SrvError(String::from(format!(
                    "send fail info: {}",
                    e.to_string()
                ))));
            }
        }
    }

    fn background_loop(
        send: Weak<MpmcQueue<SrvTransmitItem>>,
        recv: Weak<MpmcQueue<SrvTransmitItem>>,
        device: UdpSocket,
        stop_signals: Weak<AtomicU8>,
    ) -> Result<(), LokiError> {
        let Some(stop_signals) = stop_signals.upgrade() else {
            return Err(LokiError::SrvError(String::from(
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
                err = Some(LokiError::SrvError(String::from(
                    "background_loop can't upgrade send queue",
                )));
                break;
            };

            let Some(recv) = recv.upgrade() else {
                err = Some(LokiError::SrvError(String::from(
                    "background_loop can't upgrade recv queue",
                )));
                break;
            };

            let mut some_received = false;

            if !recv.is_full() {
                let mut raw_buff = [0u8; Self::MAX_MTU];
                match device.recv_from(&mut raw_buff) {
                    Ok(info_tuple) if info_tuple.0 > 0 => {
                        let mut payload = Vec::new();
                        payload.reserve(info_tuple.0);
                        payload.extend_from_slice(&raw_buff[..info_tuple.0]);
                        some_received = true;
                        recv.push_blocking(SrvTransmitItem {
                            addr: info_tuple.1,
                            payload,
                        });
                    }

                    Ok(_) => {}
                    Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                        //no error no data
                    }
                    Err(e) => {
                        err = Some(LokiError::SrvError(String::from(format!(
                            "recv_from fail info: {}",
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
                    match Self::send_with_would_block_processing(&device, &val.payload, &val.addr) {
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
                std::thread::sleep(Duration::from_millis(2));
            }
        }

        if err.is_none() {
            Ok(())
        } else {
            Err(err.unwrap())
        }
    }
}
