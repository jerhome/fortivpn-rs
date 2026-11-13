//! Suite d'options TLV arbitraire (données d'un Configure-*).
//!
//! Invariants :
//! - `parse_options` ne panique jamais ;
//! - `Ok(opts)` ⇒ `encode_options(opts) == data` (bijection exacte) ;
//! - `LcpOption`/`IpcpOption` : `from_option ∘ to_option` et `to_option ∘ from_option`
//!   sont des identités ;
//! - `ConfigOption::new` accepte exactement les valeurs ≤ 253 octets ;
//! - `ControlPacket::configure` produit un paquet dont `options()` rend la même liste.
#![no_main]

use bytes::{Bytes, BytesMut};
use libfuzzer_sys::fuzz_target;
use proto::ppp::{
    Code, ConfigOption, ControlPacket, IpcpOption, LcpOption, encode_options, parse_options,
};

fuzz_target!(|data: &[u8]| {
    let data = Bytes::copy_from_slice(data);
    match parse_options(&data) {
        Ok(opts) => {
            let total: usize = opts.iter().map(|o| 2 + o.value().len()).sum();
            assert_eq!(total, data.len());
            let mut enc = BytesMut::new();
            encode_options(&opts, &mut enc);
            assert_eq!(&enc[..], &data[..], "encode(parse(x)) != x");
            for o in &opts {
                assert!(o.value().len() <= ConfigOption::MAX_VALUE_LEN);
                let l = LcpOption::from_option(o);
                assert_eq!(&l.to_option(), o, "LcpOption non bijective");
                assert_eq!(LcpOption::from_option(&l.to_option()), l);
                let i = IpcpOption::from_option(o);
                assert_eq!(&i.to_option(), o, "IpcpOption non bijective");
                assert_eq!(IpcpOption::from_option(&i.to_option()), i);
                let n = ConfigOption::new(o.kind(), o.value().clone()).expect("new refuse");
                assert_eq!(&n, o);
            }
            if data.len() <= proto::ppp::MAX_CONTROL_DATA {
                let p = ControlPacket::configure(Code::ConfigureRequest, 1, &opts)
                    .expect("configure refuse des options valides");
                assert_eq!(p.options().as_deref(), Ok(&opts[..]));
            }
        }
        Err(_) => {
            // Il existe bien une option mal formée : on la retrouve en parcourant.
            let mut pos = 0;
            let mut found = false;
            while pos < data.len() {
                let Some(&len) = data.get(pos + 1) else {
                    found = true;
                    break;
                };
                let len = usize::from(len);
                if len < 2 || pos + len > data.len() {
                    found = true;
                    break;
                }
                pos += len;
            }
            assert!(found, "erreur sur une suite d'options valide");
        }
    }
    // Valeur arbitraire : `new` accepte ssi ≤ 253 octets.
    if let Some((&k, v)) = data.split_first() {
        let r = ConfigOption::new(k, Bytes::copy_from_slice(v));
        assert_eq!(r.is_ok(), v.len() <= ConfigOption::MAX_VALUE_LEN);
    }
});
