# PEG-TRIAGE Analysis Report

- **Generated (UTC):** 2026-10-10T09:20:28.342134+00:00
- **Score:** 157.5
- **Triage verdict:** High
- **Temporal cluster:** yes (window 120s)
- **Evidence files hashed:** 2

> Triage aid only. Low means no corroborated indicators in supplied artifacts; it does not establish a clean device.

## Scored evidence

| Timestamp | Signal | Value | Points | Source artifact | Reason |
|---|---|---|---:|---|---|
| 2026-01-15T10:15:00+00:00 | process | `com.example.pegasus_demo` | 40 | events.csv | Matched IOC: Synthetic process IOC (training only) |
| 2026-01-15T10:15:35+00:00 | domain | `https://install-demo.invalid/bootstrap` | 40 | events.csv | Matched IOC: Synthetic domain IOC (.invalid reserved domain) |
| 2026-01-15T10:16:00+00:00 | shutdown | `/private/var/db/pegasus_demo/worker` | 25 | events.csv | Matched IOC: Synthetic shutdown path (training only) |

## Input integrity

| Relative path | SHA-256 | Bytes |
|---|---|---:|
| `events.csv` | `355916b332bc0996aa4608a2e2ed6b37c3585da6e825d770e1682be941e118e2` | 381 |
| `iocs.json` | `ef021f900d54d5fff93225d000668722a70ae05e978a437434715b054dade92a` | 351 |
