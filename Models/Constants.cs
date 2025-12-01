using System;
using System.Linq;
using Stelark.Services;

namespace Stelark.Models
{
    public static class Constants
    {
        private static StelarkConfig? _config;

        private static StelarkConfig Config
        {
            get
            {
                if (_config == null)
                {
                    _config = ConfigManager.LoadConfig();
                }
                return _config;
            }
        }

        public static Guid EnrollGuid => new(Config.TechnicalConstants.EnrollGuid);
        public static Guid AutoenrollGuid => new(Config.TechnicalConstants.AutoenrollGuid);

        public static string[] AuthEKUs => Config.TechnicalConstants.AuthEKUs.ToArray();
        public static string[] ESC2EKUs => Config.TechnicalConstants.ESC2EKUs.ToArray();
        public static string[] ESC3EKUs => Config.TechnicalConstants.ESC3EKUs.ToArray();

        public static int EDITF_ATTRIBUTESUBJECTALTNAME2 => Config.TechnicalConstants.EDITF_ATTRIBUTESUBJECTALTNAME2;

        public static string[] ExcludedGroups => Config.ExcludedGroups.ToArray();
        public static string[] ExcludedUsers => Config.ExcludedUsers.ToArray();
    }
}