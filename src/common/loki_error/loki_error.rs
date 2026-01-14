#[derive(PartialEq, Eq)]
pub enum LokiError {
    TunError(String),
    SrvError(String),
    TunBrokenPipe,
    MainError(String),
    XORLenOverflow,
    XORIpv4VerifyFail,
}

impl core::fmt::Display for LokiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LokiError::TunError(s) => {
                write!(f, "Tun error: {}", s)
            }
            LokiError::SrvError(s) => {
                write!(f, "Srv error: {}", s)
            }
            LokiError::TunBrokenPipe => {
                write!(f, "Tun broken pipe")
            }
            LokiError::MainError(s) => {
                write!(f, "Main error: {}", s)
            }
            LokiError::XORLenOverflow => {
                write!(f, "XORLenOverflow")
            }
            LokiError::XORIpv4VerifyFail => {
                write!(f, "XORLenOverflow")
            }
        }
    }
}
