use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use std::{
    hint::black_box,
    io::{self, BufRead},
    time::{Duration, Instant},
};
use strongroom_poc::{decrypt, encrypt, execute_json, Context};

fn resources() -> (Option<u64>, Option<f64>) {
    // OS resource counters only; no pointer from callers enters this code.
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    if result != 0 {
        return (None, None);
    }
    let usage = unsafe { usage.assume_init() };
    let rss = usage.ru_maxrss as u64 * if cfg!(target_os = "macos") { 1 } else { 1024 };
    let cpu = usage.ru_utime.tv_sec as f64
        + usage.ru_stime.tv_sec as f64
        + (usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) as f64 / 1_000_000.0;
    (Some(rss), Some(cpu))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("bench") {
        let size: usize = args[2].parse().unwrap();
        let iterations: usize = args[3].parse().unwrap();
        let delay_ms: u64 = args[4].parse().unwrap();
        let ctx = Context {
            tenant_id: "tenant-1".into(),
            record_id: "record-1".into(),
            purpose: "api-key".into(),
        };
        let plaintext = "x".repeat(size);
        let mut samples = Vec::with_capacity(iterations);
        let mut output_bytes = 0;
        let warmups = if delay_ms > 0 { 5 } else { 100 };
        for i in 0..(iterations + warmups) {
            let start = Instant::now();
            let mut entropy = [0u8; 56];
            getrandom::fill(&mut entropy).unwrap();
            // Match the TS/Wasm path: serialize/parse JSON on both operations.
            let request = serde_json::json!({"op":"encrypt", "plaintext":plaintext, "context":ctx,"entropy":B64.encode(entropy)}).to_string();
            if delay_ms > 0 {
                std::thread::sleep(Duration::from_millis(delay_ms));
            }
            let encrypted = execute_json(&request).unwrap();
            let envelope: serde_json::Value = serde_json::from_str(&encrypted).unwrap();
            let request =
                serde_json::json!({"op":"decrypt", "envelope":envelope, "context":ctx}).to_string();
            if delay_ms > 0 {
                std::thread::sleep(Duration::from_millis(delay_ms));
            }
            let decrypted = execute_json(&request).unwrap();
            let result: serde_json::Value = serde_json::from_str(&decrypted).unwrap();
            assert_eq!(result["plaintext"].as_str().unwrap(), plaintext);
            black_box(&result);
            output_bytes = encrypted.len();
            if i >= warmups {
                samples.push(start.elapsed().as_secs_f64() * 1000.0);
            }
        }
        let total: f64 = samples.iter().sum();
        samples.sort_by(f64::total_cmp);
        let (rss, cpu) = resources();
        println!(
            "{}",
            serde_json::json!({"engine":"rust-native", "size":size,"iterations":iterations,"delayMsPerKmsCall":delay_ms,
            "p50Ms": samples[iterations/2], "p95Ms": samples[(iterations*95/100).min(iterations-1)],
            "meanMs": total / iterations as f64, "roundtripsPerSecond":iterations as f64 / (total/1000.0), "envelopeBytes": output_bytes,
            "processMaxRssBytes":rss,"processCpuSeconds":cpu})
        );
    } else if args.get(1).map(String::as_str) == Some("selfcheck") {
        let ctx = Context {
            tenant_id: "a".into(),
            record_id: "b".into(),
            purpose: "c".into(),
        };
        let mut entropy = [0; 56];
        getrandom::fill(&mut entropy).unwrap();
        let env = encrypt("synthetic", &ctx, &entropy).unwrap();
        assert_eq!(decrypt(&env, &ctx).unwrap(), "synthetic");
        println!("ok");
    } else {
        for line in io::stdin().lock().lines() {
            let output = match execute_json(&line.unwrap()) {
                Ok(value) => value,
                Err(_) => "{\"error\":\"invalid request or authentication failed\"}".into(),
            };
            println!("{output}");
        }
    }
}
