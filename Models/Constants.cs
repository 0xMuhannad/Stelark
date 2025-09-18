using System;

namespace Stelark.Models
{
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
}