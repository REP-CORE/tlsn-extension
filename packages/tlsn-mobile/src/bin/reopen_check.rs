//! reopen-check — prove that a notarized session can be re-opened NARROWER,
//! offline, without a second proof.
//!
//! This is the device-free end-to-end test for `open_presentation`. It mints one
//! real notary-signed session against a public endpoint, then builds a second,
//! narrower presentation from the SAME attestation with no notary and no server
//! in the loop, and verifies both.
//!
//! What it has to demonstrate, because the whole disclosure argument rests on it:
//!   1. the re-opened presentation still verifies against the notary key
//!   2. it reveals STRICTLY LESS than the original
//!   3. what it does reveal is the same bytes, not a re-encoding
//!   4. asking for something that was never committed FAILS rather than
//!      silently producing a smaller proof
//!
//! The first version of this committed the whole response as one range and then
//! tried to open one field out of it. That fails, and the failure is the useful
//! part: a hash commitment is ATOMIC, so an opening must tile exactly with whole
//! committed ranges. Commit granularity, chosen at proof time, is therefore the
//! hard ceiling on how narrow any later presentment can be. Hence the shape below:
//! commit two fields separately, then open one.
//!
//!   cargo run -p tlsn-mobile --bin reopen-check
//!
//! One small HTTPS request through the live notary. No device, no login.

use std::process::ExitCode;
use tlsn_mobile::{
    notarize_capture, open_presentation, verify_presentation, Handler, HandlerAction, HandlerParams,
    HandlerPart, HandlerType, HttpHeader, HttpRequest, Mode, ProverOptions,
};

/// The notary key REP pins. A valid signature proves nothing without knowing whose.
const NOTARY_KEY: &str = "02114d7e15cb2a93ad88997af3394d00008dae381b601f31379d638de492ab25ef";

fn revealed(recv: &str) -> usize {
    // Undisclosed bytes come back as 'X'. What is actually revealed is everything
    // else, so redaction is what the count has to exclude.
    recv.chars().filter(|c| *c != 'X').count()
}

fn main() -> ExitCode {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://dummyjson.com/quotes/1".into());

    let req = HttpRequest {
        url: url.clone(),
        method: "GET".into(),
        headers: vec![
            HttpHeader { name: "User-Agent".into(), value: "rep-reopen/1.0".into() },
            HttpHeader { name: "Accept".into(), value: "application/json".into() },
            HttpHeader { name: "Accept-Encoding".into(), value: "identity".into() },
            HttpHeader { name: "Connection".into(), value: "close".into() },
        ],
        body: None,
    };
    // Commit two fields as SEPARATE ranges. This is what a real template does: one
    // committed range per match. It is also the only shape a later narrowing can
    // work with, since a commitment cannot be opened in part.
    let wide_regex = r#""id"\s*:\s*[0-9]+|"author"\s*:\s*"[^"]*""#;
    let options = ProverOptions {
        verifier_url: "https://rep-notary.fly.dev".into(),
        max_sent_data: 4096,
        max_recv_data: 131_072,
        handlers: vec![Handler {
            handler_type: HandlerType::Recv,
            part: HandlerPart::All,
            action: HandlerAction::Reveal,
            params: Some(HandlerParams {
                key: None,
                hide_key: None,
                hide_value: None,
                content_type: None,
                path: None,
                regex: Some(wide_regex.into()),
                flags: None,
            }),
        }],
        mode: Some(Mode::Mpc),
    };

    eprintln!("reopen-check: GET {url} through rep-notary.fly.dev (one small request)");
    let session = match notarize_capture(req, options) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("❌ notarize failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!(
        "  session: presentation={}B attestation={}B secrets={}B",
        session.presentation.len(),
        session.attestation.len(),
        session.secrets.len()
    );

    let full = match verify_presentation(session.presentation.clone(), NOTARY_KEY.into()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("❌ the original presentation does not verify: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Narrow to a single field. Anything committed can be opened; this picks one
    // JSON member out of a response that was committed whole.
    let narrow_regex = r#""id"\s*:\s*[0-9]+"#;
    let reopened = match open_presentation(
        session.attestation.clone(),
        session.secrets.clone(),
        Some(narrow_regex.into()),
    ) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("❌ re-open failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    let narrow = match verify_presentation(reopened.clone(), NOTARY_KEY.into()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("❌ the re-opened presentation does not verify: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut failed = false;
    let mut check = |name: &str, cond: bool, detail: String| {
        if cond {
            eprintln!("  ok   {name}");
        } else {
            failed = true;
            eprintln!("  FAIL {name}: {detail}");
        }
    };

    check(
        "the re-opened proof carries the same connection",
        narrow.server_name == full.server_name && narrow.time_secs == full.time_secs,
        format!("{} @ {} vs {} @ {}", narrow.server_name, narrow.time_secs, full.server_name, full.time_secs),
    );
    check(
        "and is signed by the same notary",
        narrow.notary_key == full.notary_key,
        format!("{} vs {}", narrow.notary_key, full.notary_key),
    );
    // A valid signature proves nothing without knowing whose it is: anyone can
    // stand up a notary. Re-opening must not lose the pin.
    check(
        "which is the notary REP pins",
        full.key_matches && narrow.key_matches,
        format!("wide={} narrow={}", full.key_matches, narrow.key_matches),
    );

    let (wide_bytes, narrow_bytes) = (revealed(&full.recv), revealed(&narrow.recv));
    check(
        "it reveals strictly less than the original",
        narrow_bytes < wide_bytes,
        format!("narrow={narrow_bytes}B wide={wide_bytes}B"),
    );

    // The revealed bytes must sit at the SAME offsets, otherwise this is a
    // different document rather than a narrower view of one.
    let same_offsets = narrow
        .recv
        .chars()
        .zip(full.recv.chars())
        .all(|(n, w)| n == 'X' || n == w);
    check(
        "and every byte it does reveal is the original byte at the same offset",
        same_offsets && narrow.recv.len() == full.recv.len(),
        format!("len {} vs {}", narrow.recv.len(), full.recv.len()),
    );

    // The point of narrowing is that the field survives.
    let re = regex::Regex::new(narrow_regex).expect("static regex");
    check(
        "the field that was asked for is present in the narrowed proof",
        re.is_match(&narrow.recv),
        narrow.recv.chars().take(120).collect::<String>(),
    );

    // 4. WIDENING MUST FAIL, LOUDLY. This is the property that makes the whole
    //    path safe to ship: if a re-open could quietly return less than was asked
    //    for, a consumer would see a valid notary signature over a document that
    //    is missing the field their decision depends on, with nothing to indicate
    //    it. `"quote"` is present in the response and was deliberately NOT
    //    committed, so it is the exact shape of the mistake — asking, later, for
    //    something the proof never promised.
    let never_committed = r#""quote"\s*:\s*"[^"]*""#;
    match open_presentation(
        session.attestation.clone(),
        session.secrets.clone(),
        Some(never_committed.into()),
    ) {
        Ok(b) => {
            let leaked = verify_presentation(b, NOTARY_KEY.into())
                .map(|v| revealed(&v.recv))
                .unwrap_or(0);
            check(
                "opening a field that was never committed is refused",
                false,
                format!("it produced a proof revealing {leaked}B instead of failing"),
            );
        }
        Err(e) => check(
            "opening a field that was never committed is refused, with the bytes named",
            e.to_string().contains("cover") || e.to_string().contains("commitment"),
            e.to_string(),
        ),
    }

    // And the floor: narrowing all the way down is allowed, because "prove you
    // talked to this host and nothing else" is a legitimate presentment.
    match open_presentation(session.attestation.clone(), session.secrets.clone(), Some(
        r"matches-nothing-at-all".into(),
    )) {
        Ok(b) => match verify_presentation(b, NOTARY_KEY.into()) {
            Ok(v) => check(
                "and narrowing to the status line alone is allowed",
                revealed(&v.recv) < narrow_bytes && v.key_matches,
                format!("{}B", revealed(&v.recv)),
            ),
            Err(e) => check("the minimal narrowing still verifies", false, e.to_string()),
        },
        Err(e) => check("narrowing to the status line alone is allowed", false, e.to_string()),
    }

    // 5. The shape we would actually ship: levels built at proof time, secrets
    //    never stored. Same primitive, no plaintext at rest. Exercised here from
    //    the captured session rather than by proving a second time, because the
    //    only difference in production is WHEN it is called.
    match tlsn_mobile::presentations_for_levels(
        session.attestation.clone(),
        session.secrets.clone(),
        vec![Some(narrow_regex.into()), Some(wide_regex.into())],
    ) {
        Ok(levels) => {
            let sizes: Vec<usize> = levels
                .iter()
                .map(|b| {
                    verify_presentation(b.clone(), NOTARY_KEY.into())
                        .map(|v| revealed(&v.recv))
                        .unwrap_or(0)
                })
                .collect();
            check(
                "one session yields several levels, each a valid proof",
                levels.len() == 2 && sizes.iter().all(|s| *s > 0),
                format!("{sizes:?}"),
            );
            check(
                "and the narrow level reveals less than the wide one",
                sizes[0] < sizes[1],
                format!("narrow={}B wide={}B", sizes[0], sizes[1]),
            );
        }
        Err(e) => check("building levels at proof time works", false, e.to_string()),
    }

    if failed {
        eprintln!("\n❌ re-open is NOT sound; do not ship the disclosure-level path");
        ExitCode::FAILURE
    } else {
        eprintln!(
            "\n✅ re-open verified: {wide_bytes}B → {narrow_bytes}B revealed, offline, no second proof"
        );
        ExitCode::SUCCESS
    }
}
