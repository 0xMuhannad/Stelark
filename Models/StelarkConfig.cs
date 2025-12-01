using System;
using System.Collections.Generic;

namespace Stelark.Models
{
    public class StelarkConfig
    {
        public List<string> ExcludedGroups { get; set; } = new();
        public List<string> ExcludedUsers { get; set; } = new();
        public TechnicalConstantsConfig TechnicalConstants { get; set; } = new();
    }

    public class TechnicalConstantsConfig
    {
        public List<string> AuthEKUs { get; set; } = new();
        public List<string> ESC2EKUs { get; set; } = new();
        public List<string> ESC3EKUs { get; set; } = new();
        public string EnrollGuid { get; set; } = "0e10c968-78fb-11d2-90d4-00c04f79dc55";
        public string AutoenrollGuid { get; set; } = "a05b8cc2-17bc-4802-a710-e7c15ab866a2";
        public int EDITF_ATTRIBUTESUBJECTALTNAME2 { get; set; } = 0x00040000;
    }
}

