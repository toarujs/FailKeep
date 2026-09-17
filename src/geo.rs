//! Optional local GeoIP (feature `geo`).

use std::net::IpAddr;
use std::sync::Mutex;

#[derive(Debug, Clone, serde::Serialize)]
pub struct GeoInfo {
    pub country_code: String,
    pub country_name: String,
}

static LOOKUP: Mutex<Option<GeoLookup>> = Mutex::new(None);

pub struct GeoLookup {
    #[cfg(feature = "geo")]
    reader: maxminddb::Reader<Vec<u8>>,
}

impl GeoLookup {
    #[cfg(feature = "geo")]
    pub fn open(path: &str) -> anyhow::Result<Self> {
        let reader = maxminddb::Reader::open_readfile(path)?;
        Ok(Self { reader })
    }

    #[cfg(not(feature = "geo"))]
    pub fn open(_path: &str) -> anyhow::Result<Self> {
        anyhow::bail!("geo feature not enabled")
    }

    #[cfg(feature = "geo")]
    pub fn lookup(&self, ip: IpAddr) -> Option<GeoInfo> {
        if crate::config::is_private_ip(ip) {
            return None;
        }
        let country: maxminddb::geoip2::Country = self.reader.lookup(ip).ok()?;
        let iso = country.country?.iso_code?.to_string();
        let name = country
            .country?
            .names
            .as_ref()?
            .get("en")
            .cloned()
            .unwrap_or_else(|| iso.clone());
        Some(GeoInfo {
            country_code: iso,
            country_name: name,
        })
    }

    #[cfg(not(feature = "geo"))]
    pub fn lookup(&self, _ip: IpAddr) -> Option<GeoInfo> {
        None
    }
}

pub fn init(enabled: bool, path: &str) {
    let mut g = LOOKUP.lock().unwrap();
    if !enabled || path.is_empty() {
        *g = None;
        return;
    }
    match GeoLookup::open(path) {
        Ok(l) => *g = Some(l),
        Err(e) => {
            tracing::warn!("geo db open failed: {e:#}");
            *g = None;
        }
    }
}

/// JSON-friendly lookup for IPC: {"cc":"CN","name":"China"} or null.
pub fn lookup_ip(ip: IpAddr) -> Option<GeoInfo> {
    let g = LOOKUP.lock().unwrap();
    g.as_ref()?.lookup(ip)
}

pub fn is_private(ip: IpAddr) -> bool {
    crate::config::is_private_ip(ip)
}
