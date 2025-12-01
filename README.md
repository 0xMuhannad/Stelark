# Stelark
### The Ark that hunts the stars

**Compromise Assessment Tool for Detecting AD CS Attacks**

Stelark is an enterprise Compromise Assessment tool for detecting vulnerabilities and exploitation in Active Directory Certificate Services (AD CS) environments. It identifies known AD CS attack paths (ESC1–ESC8) and hunts for suspicious certificates that may indicate active or historical abuse for AD CS privilege escalation.

## Key Features

### 🔍 **Vulnerability Detection**
- **ESC1**: Templates with client authentication EKU and enrollee-supplied subject.
- **ESC2**: Templates with Any Purpose EKU or no EKU restrictions.
- **ESC3**: Templates with Certificate Request Agent EKU.
- **ESC4**: Templates with overly permissive access control.
- **ESC6**: CAs with `EDITF_ATTRIBUTESUBJECTALTNAME2` enabled.
- **ESC7**: CAs with vulnerable permissions.
- **ESC8**: NTLM relay to AD CS web enrollment endpoints.

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

![Stelark HTML Report Demo](assets/Stelark.gif)

*Interactive HTML report showing vulnerability detection, certificate details, and comprehensive Compromise Assessment results.*

## System Requirements

- **Target System**: Runs on Windows Certificate Authority server.
- **Permissions**: Requires administrative rights on the CA server.
- **Network**: Active Directory connectivity recommended.

## Usage

```powershell
# Standard scan
Stelark.exe

# Comprehensive scan with full certificate enumeration
Stelark.exe --intense

# Display help and options
Stelark.exe --help
```

### Scan Modes
- **Standard**: Analyzes certificate templates and hunts certificates issued from vulnerable templates.
- **Intense**: Performs a full enumeration of the certificate database; slower but more comprehensive.

## Configuration

Stelark uses `Stelark.config` to customize exclusion lists and technical constants. The configuration file is automatically created on first run if it doesn't exist.

### Exclusion Lists

**ExcludedGroups**: Groups and their members are excluded from vulnerability reporting. Certificates requested by these groups or by users who belong to these groups will not be reported as suspicious.

**ExcludedUsers**: Specific users excluded from vulnerability reporting. Certificates requested by these users will not be reported.

**How Exclusions Work:**
- Certificates requested by excluded users are excluded (direct match)
- Certificates requested by users who belong to excluded groups are excluded.
- Machine accounts (ending with `$`) and CA server accounts are automatically excluded

Supported formats: `DOMAIN\Account`, `Account`, or `Account@domain.com`. SIDs are also supported for groups.

## Output Structure

```
Stelark.zip
├── Certificates/               # Individual certificate files organized by template
├── Templates/                  # Detailed template configurations
├── Stelark Findings.json      # Detailed finding of Stelark
├── Stelark Report.html        # Interactive web report of Stelark finding (with export functionality)
├── Stelark.log                # Detailed execution log
└── output.txt                  # Console output capture
```

## Use Cases

- **Incident Response**: Detect signs of AD CS attacks and active exploitation.
- **Compromise Assessment**: Identify vulnerable configurations before they can be exploited.
- **Forensic Analysis**: Perform historical analysis of certificate issuance to uncover past abuse.
