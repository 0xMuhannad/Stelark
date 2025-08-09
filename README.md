# Stelark
### The Ark that hunts the stars

**Compromise Assessment Tool for Detecting ADCS Attacks**

Stelark is an enterprise Compromise Assessment tool for detecting vulnerabilities and exploitation in Active Directory Certificate Services (ADCS) environments. It identifies known ADCS attack paths (ESC1–ESC8) and hunts for suspicious certificates that may indicate active or historical abuse for ADCS privilege escalation.

## Key Features

### 🔍 **Vulnerability Detection**
- **ESC1**: Templates with client authentication EKU and enrollee-supplied subject.
- **ESC2**: Templates with Any Purpose EKU or no EKU restrictions.
- **ESC3**: Templates with Certificate Request Agent EKU.
- **ESC4**: Templates with overly permissive access control.
- **ESC6**: CAs with `EDITF_ATTRIBUTESUBJECTALTNAME2` enabled.
- **ESC7**: CAs with vulnerable permissions.
- **ESC8**: NTLM relay to ADCS web enrollment endpoints.

### 📋 **Certificate Analysis**
- **Suspicious Certificate Detection**: Identifies certificates issued from vulnerable templates.
- **Template Mapping**: Correlates certificates to their originating vulnerable templates.
- **Historical Attack Hunting**: Identifies past exploitation even after templates are fixed.
- **Intense Mode**: Enumerates the entire certificate database for comprehensive analysis.

### 📊 **Reporting & Output**
- **Multiple Formats**: Generates interactive HTML, structured JSON, and CSV exports.
- **Detailed Logging**: Includes comprehensive analysis logs with performance statistics.
- **Individual Files**: Stores raw certificate and template data for forensic review.
- **Auto-Packaging**: Compresses all output into a single ZIP archive.

## 📋 HTML Report Preview

![Stelark HTML Report Demo](Media/Stelark.gif)

*Interactive HTML report showing vulnerability detection, certificate details, and comprehensive Compromise Assessment results.*

## System Requirements

- **Target System**: Runs on Windows Certificate Authority server.
- **Permissions**: Requires administrative rights on the CA server.
- **Network**: Active Directory connectivity recommended.

## Usage

```powershell
# Standard scan (recommended for most assessments)
Stelark.exe

# Comprehensive scan with full certificate enumeration
Stelark.exe --intense

# Display help and options
Stelark.exe --help
```

### Scan Modes
- **Standard**: Analyzes certificate templates and hunts certificates issued from vulnerable templates.
- **Intense**: Performs a full enumeration of the certificate database; slower but more comprehensive.

## Output Structure

```
Stelark.zip
├── Certificates/               # Individual certificate files organized by template
├── Templates/                  # Detailed template configurations
├── Suspicious_Certificates.csv # Detailed certificate information in CSV format
├── Stelark_findings.json       # Detailed finding of Stelark
├── Stelark_Report.html         # Interactive web report of Stelark finding
├── stelark.log                 # Detailed execution log
└── output.txt                  # Console output capture
```

## Use Cases

- **Incident Response**: Detect signs of ADCS attacks and active exploitation.
- **Compromise Assessment**: Identify vulnerable configurations before they can be exploited.
- **Forensic Analysis**: Perform historical analysis of certificate issuance to uncover past abuse.
