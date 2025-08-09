using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Text.Json.Serialization;

namespace Stelark
{
    public class GlobalState
    {
        public bool FoundCAServers { get; set; } = false;
        public bool IsLocalCAServer { get; set; } = false;
        public List<string> CAServerHostnames { get; set; } = new();
        public string OutputDir { get; set; } = string.Empty;
        public bool AllowIntenseFallback { get; set; } = false;
        
        public List<VulnerableTemplate> ESC1VulnTemplates { get; set; } = new();
        public List<VulnerableTemplate> ESC2VulnTemplates { get; set; } = new();
        public List<VulnerableTemplate> ESC3VulnTemplates { get; set; } = new();
        public List<VulnerableTemplate> ESC4VulnTemplates { get; set; } = new();
        public List<VulnerableCA> ESC6VulnCAs { get; set; } = new();
        public List<VulnerableCAPermissions> ESC7VulnCAPermissions { get; set; } = new();
        public List<VulnerableEndpoint> ESC8VulnEndpoints { get; set; } = new();
        
        public List<Certificate> ESC1Certificates { get; set; } = new();
        public List<Certificate> ESC2Certificates { get; set; } = new();
        public List<Certificate> ESC3Certificates { get; set; } = new();
        public List<Certificate> ESC4Certificates { get; set; } = new();
        public List<Certificate> IntenseCertificates { get; set; } = new();
        public List<Certificate> IntenseUniqueCertificates { get; set; } = new();
        
        public int SuspiciousESC1CertCount { get; set; } = 0;
        public int SuspiciousESC2CertCount { get; set; } = 0;
        public int SuspiciousESC3CertCount { get; set; } = 0;
        public int SuspiciousESC4CertCount { get; set; } = 0;
        public int ESC6VulnCount { get; set; } = 0;
        public int ESC7VulnCount { get; set; } = 0;
        public int ESC8VulnCount { get; set; } = 0;
        
        public bool CertutilErrorDetected_ESC1 { get; set; } = false;
        public bool CertutilErrorDetected_ESC2 { get; set; } = false;
        public bool CertutilErrorDetected_ESC3 { get; set; } = false;
        public bool CertutilErrorDetected_ESC4 { get; set; } = false;
        public bool CertutilErrorDetected_Intense { get; set; } = false;
        public bool IntenseScanRun { get; set; } = false;
        
        public List<string> UnmappedTemplates { get; set; } = new();
    }

    public class VulnerableTemplate
    {
        public int TemplateCount { get; set; }
        public string VulnerabilityType { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public string CN { get; set; } = string.Empty;
        public string? OID { get; set; }
        public bool IsEnabled { get; set; }
        public bool SuppliesSubject { get; set; }
        public bool NoManagerApproval { get; set; }
        public bool NoRASignature { get; set; }
        public bool HasAuthEKU { get; set; }
        public bool HasCertRequestAgentEKU { get; set; }
        public bool HasAnyPurposeEKU { get; set; }
        public bool HasNoEKU { get; set; }
        public bool HasEnroll { get; set; }
        public List<string> EnrollmentGroups { get; set; } = new();
        public List<RiskyGroup> RiskyGroups { get; set; } = new();
        public List<string> EKUs { get; set; } = new(); // Store actual EKUs for HTML display
        public string VulnerabilityReason { get; set; } = string.Empty; // Specific reason for vulnerability
    }

    public class RiskyGroup
    {
        public string Group { get; set; } = string.Empty;
        public string Rights { get; set; } = string.Empty;
    }

    public class VulnerableEndpoint
    {
        public string Server { get; set; } = string.Empty;
        public string URL { get; set; } = string.Empty;
    }

    public class VulnerableCA
    {
        public string Server { get; set; } = string.Empty;
        public string VulnerabilityType { get; set; } = string.Empty;
        public string EditFlags { get; set; } = string.Empty;
        public bool HasEditfAttributeSubjectAltName2 { get; set; } = false;
        public string Description { get; set; } = string.Empty;
    }

    public class VulnerableCAPermissions
    {
        public string Server { get; set; } = string.Empty;
        public string VulnerabilityType { get; set; } = string.Empty;
        public string Principal { get; set; } = string.Empty;
        public string Permission { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public bool IsPrivilegedAccount { get; set; } = false;
    }

    public class Certificate
    {
        public string RequestID { get; set; } = string.Empty;
        public string Source { get; set; } = string.Empty;
        public string Requester { get; set; } = string.Empty;
        public string Principal { get; set; } = string.Empty;
        public string TemplateName { get; set; } = string.Empty;
        public string Template { get; set; } = string.Empty;
        public string DispositionMsg { get; set; } = string.Empty;
        public string SubmissionDate { get; set; } = string.Empty;
        public string NotBefore { get; set; } = string.Empty;
        public string NotAfter { get; set; } = string.Empty;
        public string Serial { get; set; } = string.Empty;
        public string CertHash { get; set; } = string.Empty;
        public string TemplateOID { get; set; } = string.Empty;
        public bool IsSuspicious { get; set; }
        public List<string> EKUs { get; set; } = new();
        public string RawCertutilBlock { get; set; } = string.Empty;
        
        // Enhanced SAN properties
        public bool ContainsSAN { get; set; } = false;
        public string SANUPN { get; set; } = string.Empty;

    }

    public class TemplateInfo
    {
        public string DisplayName { get; set; } = string.Empty;
        public string CN { get; set; } = string.Empty;
        public string? OID { get; set; }
        public SearchResult Result { get; set; } = null!;
    }

    public class EnrollmentInfo
    {
        public bool HasEnroll { get; set; }
        public List<string> EnrollmentGroups { get; set; } = new();
    }

    public static class Constants
    {
        // Extended Right GUIDs
        public static readonly Guid EnrollGuid = new("0e10c968-78fb-11d2-90d4-00c04f79dc55");
        public static readonly Guid AutoenrollGuid = new("a05b8cc2-17bc-4802-a710-e7c15ab866a2");

        // Authentication EKUs
        public static readonly string[] AuthEKUs = {
            "1.3.6.1.5.5.7.3.2",     // Client Authentication
            "1.3.6.1.4.1.311.20.2.2", // Smart Card Logon
            "1.3.6.1.5.2.3.4"        // PKINIT Client Authentication
        };

        // ESC2 EKUs
        public static readonly string[] ESC2EKUs = {
            "2.5.29.37.0" // Any Purpose
        };

        // ESC3 EKUs (Certificate Request Agent)
        public static readonly string[] ESC3EKUs = {
            "1.3.6.1.4.1.311.20.2.1", // Certificate Request Agent OID
            "Certificate Request Agent"  // Certificate Request Agent friendly name
        };

        // ESC6 CA Flag
        public const int EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000; // 262144 in decimal

        // Privileged Groups
        public static readonly string[] PrivilegedGroups = {
            "Domain Admins", "Enterprise Admins", "Administrators", "Schema Admins",
            "Account Operators", "Server Operators", "Backup Operators", "Print Operators",
            "Cert Publishers", "Group Policy Creator Owners", "Builtin\\Administrators", 
            "DNS Admins", "Exchange Admins", "Organization Management", "Security Admins", 
            "Security Operators", "System Managed"
        };

        // CA-specific privileged groups (expected to have CA permissions)
        public static readonly string[] CAPrivilegedGroups = {
            "Enterprise Admins", "Domain Admins", "Administrators", "Builtin\\Administrators",
            "Cert Publishers", "Certificate Managers", "CA Administrators"
        };

        // Privileged SIDs (built-in groups)
        public static readonly string[] PrivilegedSIDs = {
            "S-1-5-32-544", // Administrators
            "S-1-5-32-548", // Account Operators
            "S-1-5-32-549", // Server Operators
            "S-1-5-32-550", // Print Operators
            "S-1-5-32-551", // Backup Operators
            "S-1-5-32-522", // Cert Publishers (local group)
            "S-1-5-18",     // SYSTEM
            "S-1-5-32-555", // Remote Desktop Users
            "S-1-5-32-520"  // Group Policy Creator Owners
        };

        // Other privileged groups to resolve by name
        public static readonly string[] OtherPrivilegedGroups = {
            "Schema Admins", "Cert Publishers", "Builtin\\Administrators",
            "Domain Controllers", "Enterprise Domain Controllers"
        };
    }

    public static class Extensions
    {
        public static string SanitizeFileName(this string name)
        {
            return Regex.Replace(name, @"[\\/:*?""<>|]", "_");
        }

        public static string NormalizeRequestID(this string id)
        {
            if (Regex.IsMatch(id, @"^0x([0-9A-Fa-f]+) \((\d+)\)$"))
            {
                var match = Regex.Match(id, @"^0x([0-9A-Fa-f]+) \((\d+)\)$");
                return match.Groups[2].Value;
            }
            
            if (Regex.IsMatch(id, @"^0x([0-9A-Fa-f]+)$"))
            {
                var match = Regex.Match(id, @"^0x([0-9A-Fa-f]+)$");
                return Convert.ToInt32(match.Groups[1].Value, 16).ToString();
            }
            
            if (Regex.IsMatch(id, @"^\d+$"))
            {
                return id;
            }
            
            return id;
        }

        public static string GetRequesterUser(this string requester)
        {
            var parts = requester.Split('\\');
            return parts.Length > 1 ? parts[1] : requester;
        }

        public static string GetPrincipalUser(this string principal)
        {
            if (principal.StartsWith("SAN:upn="))
            {
                return principal.Replace("SAN:upn=", "").Split('@')[0];
            }
            else if (principal.Contains("@"))
            {
                return principal.Split('@')[0];
            }
            return principal;
        }
    }
} 