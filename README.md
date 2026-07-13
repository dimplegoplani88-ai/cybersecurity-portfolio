# 🛡 Malware Analysis Report — Dimple Goplani

Static analysis of a dual-threat malware sample (PCLocked Ransomware + RustyStealer Infostealer) obtained from MalwareBazaar.

## Sample

- **SHA256:** 21f006b546a50facaa16a666836fd7121eb00d018e9d2e04656d78e597b4db6d
- **Type:** PE32+ Executable (64-bit)
- **Threat:** PCLocked Ransomware + RustyStealer Infostealer
- **VirusTotal:** 46/71 engines

## Analysis Performed

- PE header inspection (PEStudio, CFF Explorer, DIE)
- String extraction and API import analysis
- Packer/obfuscation detection (entropy > 6.5)
- IOC extraction (file, network, host-based)
- Behavioral analysis via Any.run sandbox + VirusTotal intelligence

## Key Findings

- Packed/obfuscated binary with timestamp stomping
- File encryption + credential theft (dual threat)
- C2 communication over HTTPS to 185.225.19.12 and 91.214.44.67
- Shadow copy deletion to prevent recovery
- Browser data targeting (Chrome, Firefox, Edge, Brave)

## Skills Demonstrated

`Malware analysis` · `PE inspection` · `IOC extraction` · `Threat reporting` · `Static analysis`

## Report

Full write-up: [`malware_analysis/Malware_Analysis_Report_Dimple_Goplani_.docx`](malware_analysis/Malware_Analysis_Report_Dimple_Goplani_.docx)

## Legal Notice

> This analysis was performed on a sample obtained from a public malware repository for
> research and educational purposes only, in an isolated/sandboxed environment.

## Author

**Dimple Goplani** | [LinkedIn](https://www.linkedin.com/in/dimplegoplani-61a9b3315)
BCA – Computational Science | MSc Cybersecurity – Kaushalya The Skill University (in progress) | Cygnet.One Data Engineer (2024–2025)
