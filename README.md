# Odineye
Threat Profiling Using MITRE CTI

## Overview

This tool generates a threat profile Excel report based on the MITRE ATT&CK dataset. It allows users to input specific adversary groups and outputs a report showing the Tactics, Techniques, and Procedures (TTPs) associated with those groups. The report also includes a risk rating for each TTP based on how frequently it is used across the selected adversary groups.

## Features

- **Adversary-Specific TTP Analysis**: Generates a report of TTPs used by specified adversary groups.
- **Risk Assessment**: Assigns a risk rating (Critical, High, Medium, Low) based on the frequency of TTP usage across the adversaries.
- **Excel Export**: Outputs the results to an Excel file for easy analysis and sharing.

## Requirements

- Python 3.x
- Required Python packages:
  - `pandas`
  - `openpyxl`

You can install the required packages using pip:

```
bash
pip install pandas openpyxl 
```

## Installation

- Clone the MITRE ATT&CK CTI Repository:
- Clone the enterprise-attack folder from the MITRE CTI repository using git sparse-checkout.

```
mkdir mitre_cti
cd mitre_cti
git init
git remote add origin https://github.com/mitre/cti.git
git sparse-checkout init --cone
git sparse-checkout set enterprise-attack
git pull origin master
```
- Download the Script:
- Place the Threat_Profiling.py script in the same directory as the cloned enterprise-attack folder.

# Usage

Run the Script:

Execute the script from the command line:
```
bash
Copy code
python Threat_Profiling.py
Enter Adversary Groups:
```
When prompted, enter the names of the adversaries you want to analyze, separated by commas. For example:
```
Enter the names of the adversaries you want to include, separated by commas: 

Example: APT29, FIN6, APT28
```

The tool will match the entered names with those in the MITRE dataset and notify you if any groups are not found.

## Output:

The script generates an Excel file named threat_profile.xlsx with the following columns:

- TTP ID: The identifier of the TTP.
- TTP Name: The name of the TTP.
- Kill Chain Phases: The phases of the kill chain associated with the TTP.
- Adversary Group: A column for each adversary group showing whether they use the TTP (yes or no).
- TTP Frequency: The number of adversary groups that use the TTP.
- Risk Rating: The risk rating assigned based on TTP frequency (Critical, High, Medium, Low).

## Notes
- The script will exclude any adversary group names that do not exist in the MITRE dataset.
- If no valid adversary groups are provided, the script will exit without generating a report.