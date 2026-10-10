# PEG-TRIAGE: Methodology and Technical Design

## Project abstract

PEG-TRIAGE is an offline reference implementation of a transparent triage pipeline for acquired mobile-forensic records. It records SHA-256 hashes of supported source artifacts, normalizes process, domain, shutdown-log, network, profile, and crash observations, compares applicable observations against a supplied IOC set, and emits a time-ordered evidence log with explicit point contributions. A small self-contained HTML dashboard presents the result without external network requests. The project demonstrates how multiple artifact classes can be correlated under a repeatable process; it does not acquire a mobile device and is not a validated malware detector.

## Research basis

The case study and implementation draw on the preservation, acquisition, examination, analysis, and reporting lifecycle in NIST SP 800-101 Rev. 1. Amnesty International's published methodology and MVT provide a reproducible basis for examining acquired iOS/Android artifacts and IOC matches. Citizen Lab's independent review illustrates the value of corroboration and peer review. Kaspersky's iShutdown research motivates treating Shutdown.log as a useful additional artifact source. See references in the main README.

## Pipeline

1. **Scope and provenance:** The analyst supplies an evidence directory containing exported JSON, normalized CSV, or Shutdown.log text. Original input files are opened read-only and SHA-256 hashed. An optional custody CSV can be checked before parsing.
2. **Normalization:** Recognized records become `{source, timestamp, signal_type, value, detail}` records. Source filenames help infer the type of MVT module export where the row itself has no explicit type.
3. **Indicator matching:** A simple case IOC JSON format or the supported subset of STIX 2 equality patterns is used for process names, domains, and file paths.
4. **Heuristic scoring:** The case-study proposal assigns 40 points to a matching process or domain, 25 to a shutdown anomaly, 20 to an explicitly classified unknown-binary network event, and 10 to profile/crash context. When two different signal types with timestamps occur within the configured window, the sum is multiplied by 1.5.
5. **Reporting:** Findings are sorted by timestamp and emitted in Markdown, JSON, CSV, and a self-contained HTML dashboard. The report preserves the input hashes and explains each scored observation.

## Decision model

| Signal | Points | Interpretation |
|---|---:|---|
| Process name matching an IOC | 40 | High-specificity match within supplied IOC coverage |
| Domain matching an IOC | 40 | High-specificity match within supplied IOC coverage |
| Shutdown-log suspicious path / sticky event | 25 | Medium-specificity lead requiring review |
| Analyst-labeled unknown-binary network egress | 20 | Medium-specificity contextual signal |
| Profile or crash context | 10 | Low-specificity context |
| Two different signal types inside the time window | x1.5 | Correlation multiplier |

The prototype maps scores of 60+ to High, 30-59 to Medium, and below 30 to Low. These are the case study's proposed weights and thresholds; they are not empirically calibrated. A score is an explanation aid, not a probability. A Low score only describes the records provided to this run.

## Input model and supported formats

- JSON arrays of records and common MVT module exports (`netusage.json`, `shutdown_log.json`, `cache_files.json`, and similar exports).
- CSV records with `timestamp,signal_type,value,detail` columns.
- Text/log inputs named `Shutdown.log` or with `shutdown` in the filename. The generic parser extracts timestamped process-path lines for triage only; it is not a replacement for MVT/iShutdown's artifact-specific parsing.
- IOC JSON arrays under `process`, `domain`, and `path`, or STIX 2 indicators whose patterns use equality clauses for `process:name`, `domain-name:value`, `file:name`, or `file:path`.

Raw SQLite databases, encrypted backups, device acquisition, and full STIX pattern evaluation are out of scope. Run an appropriate acquisition/parser such as MVT first and preserve its output and command log as part of the case record.

## Validation and limitations

The checked-in demo is fabricated, deterministic, and uses `.invalid` example domains. It is intended to show how the report is formed, not to represent observed infection evidence. IOC coverage is time-dependent. Artifact availability depends on acquisition quality, platform/version, and the parser used. A report cannot establish attribution, infection, or absence of compromise by itself. Any real case needs authorization, evidence minimization, independent review, and a qualified examiner.

## Privacy and security

Analysis is local; the generated HTML contains report content and makes no external requests. Reports can include sensitive values from evidence, so store and share them using the case's access and retention rules. Only use evidence you are authorized to examine.
