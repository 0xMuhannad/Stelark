using System.Collections.Generic;

namespace Stelark.Models
{
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

        // Client Information properties
        public string Machine { get; set; } = string.Empty;
        public string Process { get; set; } = string.Empty;


        /// <summary>
        /// Reset certificate object to default state for object pooling
        /// </summary>
        public void Reset()
        {
            RequestID = string.Empty;
            Source = string.Empty;
            Requester = string.Empty;
            Principal = string.Empty;
            TemplateName = string.Empty;
            Template = string.Empty;
            DispositionMsg = string.Empty;
            SubmissionDate = string.Empty;
            NotBefore = string.Empty;
            NotAfter = string.Empty;
            Serial = string.Empty;
            CertHash = string.Empty;
            TemplateOID = string.Empty;
            IsSuspicious = false;
            EKUs.Clear();
            RawCertutilBlock = string.Empty;
            ContainsSAN = false;
            SANUPN = string.Empty;
            Machine = string.Empty;
            Process = string.Empty;
        }
    }
}