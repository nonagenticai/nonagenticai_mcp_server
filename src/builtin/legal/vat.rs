//! Polish VAT taxpayer whitelist (Biała lista, wl-api.mf.gov.pl): `legal_vat_whitelist`.
//!
//! The MF API caps search calls per day (~100 per IP, not verified), so successful search
//! answers are cached in-process for 24 h per (nip, date).

use std::sync::{Arc, LazyLock};
use std::time::Duration;

use regex::Regex;
use serde_json::{Map, Value, json};

use crate::builtin::{BuiltinProvider, BuiltinTool, boxed};

use super::{
    Clients, Service, TtlCache, argument, child, optional_string, parse_iso_date, schema,
    shown_str_slice, success, truthy, warsaw_today,
};

/// A NIP is exactly ten digits after whitespace, dashes and an optional `PL` are removed.
static NIP_BODY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\A[0-9]{10}\z").expect("the NIP pattern is valid"));
/// A Polish NRB is exactly 26 digits.
static NRB: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\A[0-9]{26}\z").expect("the NRB pattern is valid"));
/// The reference's `re.sub(r"[\s-]", "", nip)`.
static NIP_STRIP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[\s-]").expect("the NIP strip pattern is valid"));
/// The reference's `re.sub(r"\s", "", account)`.
static ACCOUNT_STRIP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\s").expect("the account strip pattern is valid"));

/// The NIP checksum weights.
const NIP_WEIGHTS: [u32; 9] = [6, 5, 7, 2, 3, 4, 5, 6, 7];

/// Successful search answers, per (nip, date).
static SEARCH_CACHE: LazyLock<TtlCache> =
    LazyLock::new(|| TtlCache::new(2048, Duration::from_secs(24 * 3600)));

/// Empty the whitelist cache (the reference's `clear_cache` test hook).
pub fn clear_cache() {
    SEARCH_CACHE.clear();
}

/// Validate a NIP and return its ten digits (with the checksum checked).
pub fn nip_digits(nip: &Value) -> Result<String, String> {
    let raw = match nip.as_str() {
        Some(text) => NIP_STRIP.replace_all(text, "").into_owned(),
        None => String::new(),
    };
    let raw = raw.strip_prefix("PL").unwrap_or(&raw).to_owned();
    if !NIP_BODY.is_match(&raw) {
        return Err(format!(
            "[permanent] invalid nip: {} (expected 10 digits)",
            shown_str_slice(nip)
        ));
    }
    let checksum: u32 = raw
        .chars()
        .take(9)
        .zip(NIP_WEIGHTS)
        .map(|(digit, weight)| digit.to_digit(10).unwrap_or(0) * weight)
        .sum::<u32>()
        % 11;
    let last = raw.chars().nth(9).and_then(|digit| digit.to_digit(10));
    if last != Some(checksum) {
        return Err(format!(
            "[permanent] invalid nip: {raw} (checksum mismatch)"
        ));
    }
    Ok(raw)
}

/// Validate a bank account and return its 26-digit NRB.
pub fn account_digits(account: &Value) -> Result<String, String> {
    let raw = match account.as_str() {
        Some(text) => ACCOUNT_STRIP.replace_all(text, "").into_owned(),
        None => String::new(),
    };
    let raw = raw.strip_prefix("PL").unwrap_or(&raw).to_owned();
    if !NRB.is_match(&raw) {
        return Err("[permanent] invalid account: expected a 26-digit Polish NRB".to_owned());
    }
    Ok(raw)
}

/// The reference's `_date`: a `YYYY-MM-DD` date, or today in Europe/Warsaw.
fn query_date(value: Option<String>) -> Result<String, String> {
    match value {
        None => Ok(warsaw_today()),
        Some(text) => match parse_iso_date(&text) {
            Some(date) => Ok(date.format("%Y-%m-%d").to_string()),
            None => Err("[permanent] invalid date: expected YYYY-MM-DD".to_owned()),
        },
    }
}

/// Check a Polish VAT taxpayer on the Ministry of Finance whitelist.
pub async fn whitelist(clients: &Clients, arguments: &Map<String, Value>) -> Result<Value, String> {
    let nip = nip_digits(&argument(arguments, "nip"))?;
    let on = query_date(optional_string(arguments, "date")?)?;
    let client = clients.get(Service::MfWl)?;
    let account = argument(arguments, "account");
    if !account.is_null() {
        let nrb = account_digits(&account)?;
        let answer = client
            .get_json(
                &format!("/api/check/nip/{nip}/bank-account/{nrb}"),
                &[("date", on.clone())],
                None,
            )
            .await?;
        let result = child(&answer, "result");
        return Ok(json!({
            "nip": nip,
            "date": on,
            "account": nrb,
            "account_assigned": child(result, "accountAssigned").as_str() == Some("TAK"),
            "request_id": child(result, "requestId"),
        }));
    }
    let key = format!("{nip}|{on}");
    if let Some(cached) = SEARCH_CACHE.get(&key) {
        let Value::Object(mut fields) = cached else {
            unreachable!("a cached whitelist answer is an object");
        };
        fields.insert("cached".to_owned(), Value::Bool(true));
        return Ok(Value::Object(fields));
    }
    let answer = client
        .get_json(
            &format!("/api/search/nip/{nip}"),
            &[("date", on.clone())],
            None,
        )
        .await?;
    let result = child(&answer, "result");
    let subject = child(result, "subject");
    let accounts = match child(subject, "accountNumbers").as_array() {
        Some(items) => items.len(),
        None => 0,
    };
    let mut out = Map::new();
    out.insert("nip".to_owned(), Value::String(nip));
    out.insert("date".to_owned(), Value::String(on));
    out.insert("found".to_owned(), Value::Bool(truthy(subject)));
    out.insert("name".to_owned(), child(subject, "name").clone());
    out.insert("status_vat".to_owned(), child(subject, "statusVat").clone());
    out.insert("regon".to_owned(), child(subject, "regon").clone());
    out.insert("krs".to_owned(), child(subject, "krs").clone());
    out.insert(
        "registration_date".to_owned(),
        child(subject, "registrationLegalDate").clone(),
    );
    out.insert(
        "removal_date".to_owned(),
        child(subject, "removalDate").clone(),
    );
    out.insert("accounts_count".to_owned(), Value::from(accounts));
    out.insert("request_id".to_owned(), child(result, "requestId").clone());
    let value = Value::Object(out);
    SEARCH_CACHE.put(key, value.clone());
    let Value::Object(mut fields) = value else {
        unreachable!("the whitelist answer is an object");
    };
    fields.insert("cached".to_owned(), Value::Bool(false));
    Ok(Value::Object(fields))
}

/// Register the VAT whitelist tool.
pub fn register(provider: &mut BuiltinProvider) {
    provider.register(BuiltinTool::new(
        "legal",
        "vat_whitelist",
        "Check a Polish VAT taxpayer on the Ministry of Finance whitelist by NIP: VAT status\n\
         (\"Czynny\" active, \"Zwolniony\" exempt, or not registered), name, REGON, KRS, dates and the\n\
         number of registered bank accounts. With `account` (26-digit NRB) it instead answers whether\n\
         that account is registered for the NIP on the date (default today, Europe/Warsaw).",
        schema(json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "nip": {"type": "string"},
                "date": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": null},
                "account": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": null},
            },
            "required": ["nip"],
        })),
        Arc::new(|_caller, arguments| {
            boxed(async move { success(whitelist(&Clients::from_env(), &arguments).await?) })
        }),
    ));
}
