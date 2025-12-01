namespace Stelark.Models
{
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
}