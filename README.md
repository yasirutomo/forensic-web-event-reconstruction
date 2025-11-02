# Forensic Web Event Reconstruction

This repository contains tools and workflow for reconstructing web attack events using:

- **Plaso (log2timeline)** for timeline generation  
- **Custom Log Decoder** for decoding suspicious encoded web commands  
- **Simple Event Correlator (SEC)** for event correlation and attack chain reconstruction  

---

## Requirements

- Python 3.x
- Plaso  
  https://plaso.readthedocs.io/
- Simple Event Correlator (SEC)  
  https://simple-evcorr.github.io/

---

## Folder Structure
```bash
dataset/
├── evidences/ # Source evidence logs
├── plaso-output.plaso # Generated Plaso file
├── plaso-result.csv # Exported timeline CSV
└── decoded.log # Output from log decoder

---

## Workflow
### 1. Generate Plaso Storage File
* in Plaso directory:
> log2timeline --storage_file=../dataset/plaso-output.plaso --timezone UTC --preferred_year 2022 ../dataset/evidences
### 2. Export to CSV
* in Plaso directory:
> psort -o l2tcsv -w data/plaso-result.csv data/plaso-output.plaso
### 3. Run Log Decoder
> python log-decoder.py --csv dataset/plaso-result.csv --out dataset/decoded.log
### 4. Run SEC
* Copy the rule file: web-attack-rules.conf → SEC rules directory 
* in SEC directory:
> cat ../dataset/decoded.log | ./sec -conf=../dataset/web-attack-rules.conf -input=-

---

## Ouput
decoded.log (Log Decoder output): timeline log with decoded payloads
fer-web-result.log (SEC output): correlated attack sequence based on rules