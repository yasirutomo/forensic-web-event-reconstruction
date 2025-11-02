# Forensic Web Event Reconstruction

This repository contains tools and workflow for web attack event reconstruction using:

- **Plaso (log2timeline)** for timeline generation  
- **Custom Log Decoder** for decoding suspicious encoded web commands in logs 
- **Simple Event Correlator (SEC)** for event correlation and attack chain reconstruction using custom rules  

## Requirements

- Python 3.12
- requirements.txt
- Plaso  
  https://plaso.readthedocs.io/
- Simple Event Correlator (SEC)  
  https://simple-evcorr.github.io/

## Dataset Folder Structure
```bash
dataset/
├── evidences/ # Source evidence logs (change the evidences based on the case)
├── plaso-output.plaso # Generated Plaso file from dataset/evidences
├── plaso-result.csv # Exported timeline CSV from plaso
├── decoded.log # Output from log decoder
└── fer-web-result.log # Output from SEC web attack rule
```

## Workflow
### 1. Generate Plaso Storage File
* in Plaso directory:
```bash 
log2timeline --storage_file=../dataset/plaso-output.plaso --timezone UTC --preferred_year 2022 ../dataset/evidences
```
* in Plaso directory:
```bash 
psort -o l2tcsv -w ../dataset/plaso-result.csv ../dataset/plaso-output.plaso
```
### 2. Run Log Decoder
```bash 
python log-decoder.py --csv dataset/plaso-result.csv --out dataset/decoded.log
```
### 3. Run SEC
* Copy the rule file: web-attack-rules.conf → SEC rules directory 
* in SEC directory:
```bash 
cat ../dataset/decoded.log | ./sec -conf=../dataset/web-attack-rules.conf -input=-
```

## Ouput
* decoded.log (Log Decoder output): timeline log with decoded payloads
* fer-web-result.log (SEC output): web attack sequence based on rules