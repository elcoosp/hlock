#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = hlock::payload::unpack_payload(data, 0);
});
