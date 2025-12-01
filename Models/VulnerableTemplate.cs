using System.Collections.Generic;

namespace Stelark.Models
{
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
}