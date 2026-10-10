# PEG-TRIAGE

**Pegasus and Mercenary-Spyware Triage** is a small, offline Python command-line project based on the proposed framework in the accompanying digital-forensics case study. It hashes supplied acquisition/export files, normalizes selected records, checks them against analyst-supplied indicators, correlates findings in time, and writes an explainable Markdown, JSON, and CSV report.

**GitHub repository:** https://github.com/sukaransingh123/peg-triage

## What it does

- Reads already-acquired MVT JSON exports and normalized CSV records, plus plain Shutdown.log text.
- Computes SHA-256 for each supported input file and can verify a custody CSV before analysis.
- Supports a practical IOC JSON format and a limited STIX 2 bundle subset (`process:name`, `domain-name:value`, `file:name`, and `file:path` equality patterns).
- Applies the case-study weights: process/domain match 40, shutdown anomaly 25, explicitly labeled unknown-binary network egress 20, and profile/crash context 10.
- Applies a 1.5 multiplier when distinct signal types occur inside the configured window; reports High at 60+, Medium at 30-59, and Low below 30.
- Produces a sorted timeline and records the reason and source file for every scored finding.

This project is a transparent student reference implementation, not a validated Pegasus detector. It does not access a phone, acquire/decrypt a backup, execute MVT or iShutdown, or establish infection from a score. It analyzes files supplied by the examiner. **Low means no corroborated indicators were found in the supplied records; it does not mean the device is clean.** A high score is a triage signal for manual expert review, not an attribution or forensic conclusion.

## Requirements

- Python 3.10 or newer
- No third-party Python packages
- Optional: [MVT](https://docs.mvt.re/) for producing forensic exports from an authorized acquisition

## Run the synthetic demo

macOS / Linux:

```sh
cd peg-triage
chmod +x run.sh peg-triage
./run.sh --demo
```

Windows Command Prompt:

```bat
cd peg-triage
run.bat --demo
```

The demo uses only fabricated data. It writes `report.md`, `report.json`, and `timeline.csv` under `peg-triage-results/`.

## Analyze acquired/exported evidence

First acquire evidence with the process authorized for your case. For example, MVT documents how to analyze an iOS backup and save JSON output:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install mvt
mvt-ios check-backup --output ./mvt-export /path/to/acquired/ios-backup
```

For an iOS sysdiagnose:

```sh
mvt-ios check-sysdiagnose --output ./mvt-export /path/to/sysdiagnose.tar.gz
```

Then correlate the exported records with an IOC file:

```sh
./run.sh --evidence ./mvt-export --iocs ./case-iocs.json --out ./case-report
```

You can also supply a folder of normalized CSV records or a plain `Shutdown.log`:

```sh
./run.sh --evidence ./acquired-exports --iocs ./case-iocs.json --window 120 --out ./case-report
```

The normalized CSV columns are `timestamp,signal_type,value,detail`. Supported `signal_type` values include `process`, `domain`, `shutdown`, `unknown_network`, `profile`, and `crash`. For `unknown_network`, explicitly label only records where the acquisition/analyst supports that classification. JSON input is accepted as arrays of records; MVT module export filenames such as `netusage.json`, `shutdown_log.json`, and `cache_files.json` help infer record types.

### IOC file formats

Simple PEG-TRIAGE JSON:

```json
{
  "process": [{"value": "process-name", "name": "case IOC 1"}],
  "domain": [{"value": "example.invalid", "name": "case IOC 2"}],
  "path": [{"value": "/path/to/indicator", "name": "case IOC 3"}]
}
```

The parser also accepts basic STIX 2 bundles with indicator patterns using `process:name`, `domain-name:value`, `file:name`, or `file:path` equality checks. IOC content should come from a trusted, current source and be preserved with the case record. The demo IOC file is fabricated and is not a real threat feed.

### Optional SHA-256 custody check

Create a CSV containing `path,sha256` entries relative to the evidence directory, then pass it as `--manifest`. All listed hashes must match or analysis stops. PEG-TRIAGE always hashes the supported input files and includes hashes in its reports, even without a supplied manifest.

## Output files

- `report.md`: readable summary, finding explanations, and input hashes.
- `report.json`: structured report, full sorted timeline, and evidence log.
- `timeline.csv`: tabular timeline.

## Project layout

```text
peg-triage/
├── peg_triage/             # Python implementation
├── examples/synthetic_case # fabricated demo records and IOC set
├── peg-triage               # executable Python launcher
├── run.sh                   # macOS/Linux launcher
├── run.bat                  # Windows launcher
└── README.md
```

## Research basis

The report's methodology is informed by NIST mobile-device forensic guidance, Amnesty International's published Pegasus forensic methodology and MVT, the Citizen Lab's independent review, and Kaspersky's public Shutdown.log/iShutdown research. These sources support analyzing acquired artifacts and treating findings as contextual forensic evidence; PEG-TRIAGE's scoring weights and temporal multiplier are the project's proposed model and have not been empirically validated.

- NIST, [SP 800-101 Rev. 1: Guidelines on Mobile Device Forensics](https://doi.org/10.6028/NIST.SP.800-101r1)
- Amnesty International, [Forensic Methodology Report: How to Catch NSO Group's Pegasus](https://www.amnesty.org/en/documents/doc10/4487/2021/en/)
- Amnesty International, [Mobile Verification Toolkit documentation](https://docs.mvt.re/en/stable/)
- Citizen Lab, [Independent Peer Review of Amnesty International's Forensic Methods](https://citizenlab.ca/amnesty-peer-review/)
- Kaspersky, [iShutdown: Pegasus, Reign and Predator indicators in Shutdown.log](https://www.kaspersky.co.uk/about/press-releases/kaspersky-reveals-new-method-to-detect-pegasus-spyware)

## Responsible use

Only analyze evidence you are authorized to examine. Work from verified copies, minimize access to personal data, document acquisition and handling, and follow applicable institutional and legal requirements. Use independent forensic review for any consequential decision.

## License

MIT License. See [LICENSE](LICENSE).
