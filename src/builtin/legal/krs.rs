//! Polish National Court Register (KRS) current extract: `legal_krs_extract`.

use std::sync::{Arc, LazyLock};

use regex::Regex;
use serde_json::{Map, Value, json};

use crate::builtin::{BuiltinProvider, BuiltinTool, boxed};

use super::{
    Clients, Service, child, child_or, enum_or, python_str, schema, shown_str_slice, success,
    truthy,
};

/// The reference's `_KRS`: up to ten digits.
static KRS_NUMBER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\A\d{1,10}\z").expect("the KRS pattern is valid"));

/// The reference's `MAX_ACTIVITIES`.
const MAX_ACTIVITIES: usize = 10;

/// Python's `" ".join(p for p in parts if p)` over JSON values.
fn join_truthy(parts: &[&Value], separator: &str) -> String {
    parts
        .iter()
        .filter(|part| truthy(part))
        .map(|part| python_str(part))
        .collect::<Vec<_>>()
        .join(separator)
}

/// The reference's `_address`: street and number, flat, postcode and town, country.
fn address(adres: &Value) -> Value {
    if !truthy(adres) {
        return Value::Null;
    }
    let mut street = join_truthy(&[child(adres, "ulica"), child(adres, "nrDomu")], " ");
    if truthy(child(adres, "nrLokalu")) {
        street.push('/');
        street.push_str(&python_str(child(adres, "nrLokalu")));
    }
    let city = join_truthy(
        &[child(adres, "kodPocztowy"), child(adres, "miejscowosc")],
        " ",
    );
    let mut parts: Vec<String> = Vec::new();
    if !street.is_empty() {
        parts.push(street);
    }
    if !city.is_empty() {
        parts.push(city);
    }
    if truthy(child(adres, "kraj")) {
        parts.push(python_str(child(adres, "kraj")));
    }
    if parts.is_empty() {
        Value::Null
    } else {
        Value::String(parts.join(", "))
    }
}

/// The reference's `_activities`: up to ten PKD codes, predominant first.
fn activities(dzial3: &Value) -> Value {
    let subject = child(dzial3, "przedmiotDzialalnosci");
    let mut out: Vec<Value> = Vec::new();
    for (key, predominant) in [
        ("przedmiotPrzewazajacejDzialalnosci", true),
        ("przedmiotPozostalejDzialalnosci", false),
    ] {
        for activity in child(subject, key).as_array().cloned().unwrap_or_default() {
            let code = [
                child(&activity, "kodDzial"),
                child(&activity, "kodKlasa"),
                child(&activity, "kodPodklasa"),
            ]
            .iter()
            .filter(|part| truthy(part))
            .map(|part| python_str(part))
            .collect::<Vec<_>>()
            .join(".");
            out.push(json!({
                "code": code,
                "description": child(&activity, "opis"),
                "predominant": predominant,
            }));
            if out.len() >= MAX_ACTIVITIES {
                break;
            }
        }
        if out.len() >= MAX_ACTIVITIES {
            break;
        }
    }
    Value::Array(out)
}

/// The reference's `_representation`: the body's name, how it represents, its members.
fn representation(dzial2: &Value) -> Value {
    let raw = child(dzial2, "reprezentacja");
    let null = Value::Null;
    // Some entities list several bodies; the reference takes the first.
    let rep: &Value = match raw.as_array() {
        Some(items) => items.first().unwrap_or(&null),
        None => raw,
    };
    let mut members: Vec<Value> = Vec::new();
    for member in child(rep, "sklad").as_array().cloned().unwrap_or_default() {
        let first = child(child(&member, "imiona"), "imie");
        let last = child(child(&member, "nazwisko"), "nazwiskoICzlon");
        let name = join_truthy(&[first, last], " ");
        members.push(json!({
            "name": if name.is_empty() { Value::Null } else { Value::String(name) },
            "function": child(&member, "funkcjaWOrganie"),
        }));
    }
    json!({
        "body": child(rep, "nazwaOrganu"),
        "method": child(rep, "sposobReprezentacji"),
        "members": members,
    })
}

/// Current KRS extract of a Polish company / organisation by KRS number.
pub async fn extract(clients: &Clients, arguments: &Map<String, Value>) -> Result<Value, String> {
    let krs_value = super::argument(arguments, "krs");
    let Some(krs) = krs_value.as_str() else {
        return Err(format!(
            "[permanent] invalid krs: {} (expected up to 10 digits)",
            shown_str_slice(&krs_value)
        ));
    };
    if !KRS_NUMBER.is_match(krs.trim()) {
        return Err(format!(
            "[permanent] invalid krs: {} (expected up to 10 digits)",
            shown_str_slice(&krs_value)
        ));
    }
    let register = enum_or(arguments, "register", "P", &["P", "S"])?;
    let number = format!("{:0>10}", krs.trim());
    let client = clients.get(Service::Krs)?;
    let answer = client
        .get_json(
            &format!("/api/krs/OdpisAktualny/{number}"),
            &[("rejestr", register), ("format", "json".to_owned())],
            Some("KRS entry not found in this register"),
        )
        .await?;
    let odpis = child(&answer, "odpis");
    let header = child(odpis, "naglowekA");
    let dane = child(odpis, "dane");
    let dzial1 = child(dane, "dzial1");
    let subject = child(dzial1, "danePodmiotu");
    let identifiers = child(subject, "identyfikatory");
    let capital = child(child(dzial1, "kapital"), "wysokoscKapitaluZakladowego");
    let number_value = Value::String(number.clone());
    let header_number = child_or(header, "numerKRS", &number_value);
    Ok(json!({
        "krs": header_number,
        "as_of": child(header, "stanZDnia"),
        "name": child(subject, "nazwa"),
        "legal_form": child(subject, "formaPrawna"),
        "nip": child(identifiers, "nip"),
        "regon": child(identifiers, "regon"),
        "address": address(child(child(dzial1, "siedzibaIAdres"), "adres")),
        "capital": if truthy(capital) {
            json!({"amount": child(capital, "wartosc"), "currency": child(capital, "waluta")})
        } else {
            Value::Null
        },
        "representation": representation(child(dane, "dzial2")),
        "business_activity": activities(child(dane, "dzial3")),
    }))
}

/// Register the KRS tool.
pub fn register(provider: &mut BuiltinProvider) {
    provider.register(BuiltinTool::new(
        "legal",
        "krs_extract",
        "Current KRS extract of a Polish company / organisation by KRS number (register \"P\" =\n\
         entrepreneurs, \"S\" = associations/foundations): name, legal form, NIP, REGON, address,\n\
         share capital, who represents it and how, main business activities. Personal names are\n\
         masked by the source.",
        schema(json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "krs": {"type": "string"},
                "register": {"default": "P", "enum": ["P", "S"], "type": "string"},
            },
            "required": ["krs"],
        })),
        Arc::new(|_caller, arguments| {
            boxed(async move { success(extract(&Clients::from_env(), &arguments).await?) })
        }),
    ));
}
