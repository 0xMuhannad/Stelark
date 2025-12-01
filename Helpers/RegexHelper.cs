using System;
using System.Text.RegularExpressions;

namespace Stelark.Helpers
{
    /// <summary>
    /// Optimized regex patterns compiled for better performance
    /// </summary>
    public static class RegexHelper
    {
        // Certificate parsing patterns (compiled for performance)
        public static readonly Regex RowPattern = new(@"^Row [0-9]+:", RegexOptions.Compiled);
        public static readonly Regex OidPattern = new(@"^[0-9]+(\.[0-9]+)+$", RegexOptions.Compiled);
        public static readonly Regex SerialNumberPattern = new(@"Serial Number: ""?([^""\r\n]+)""?", RegexOptions.Compiled);
        public static readonly Regex EnhancedKeyUsagePattern = new(@"^\s*Enhanced Key Usage\s*$", RegexOptions.Compiled);
        public static readonly Regex ApplicationPoliciesPattern = new(@"^\s*Application Policies\s*$", RegexOptions.Compiled);
        public static readonly Regex WhitespacePattern = new(@"^\s+", RegexOptions.Compiled);
        public static readonly Regex EkuLinePattern = new(@"([A-Za-z0-9 .\-]+)?\s*\(?([0-9.]+)\)?", RegexOptions.Compiled);

        // CA server patterns
        public static readonly Regex CaNamePattern = new(@"Server\s+""([^""]+)""", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        public static readonly Regex EditFlagsPattern = new(@"EditFlags.*?(\d+)", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        public static readonly Regex FqdnPattern = new(@"^[a-z]+\.[a-z]+$", RegexOptions.Compiled);

        // Request ID normalization patterns
        public static readonly Regex RequestIdHexWithDecimalPattern = new(@"^0x([0-9A-Fa-f]+) \((\d+)\)$", RegexOptions.Compiled);
        public static readonly Regex RequestIdHexPattern = new(@"^0x([0-9A-Fa-f]+)$", RegexOptions.Compiled);
        public static readonly Regex RequestIdDecimalPattern = new(@"^\d+$", RegexOptions.Compiled);

        // File name sanitization pattern
        public static readonly Regex FileNameSanitizePattern = new(@"[\\/:*?""<>|]", RegexOptions.Compiled);

        // Helper methods for common operations
        public static bool IsRowStart(string line)
        {
            return line.StartsWith("Row ") && RowPattern.IsMatch(line);
        }

        public static bool IsOidFormat(string template)
        {
            return OidPattern.IsMatch(template);
        }

        public static bool IsEnhancedKeyUsage(string line)
        {
            return EnhancedKeyUsagePattern.IsMatch(line) || ApplicationPoliciesPattern.IsMatch(line);
        }

        public static bool IsWhitespaceLine(string line)
        {
            return WhitespacePattern.IsMatch(line);
        }

        public static Match GetSerialNumberMatch(string line)
        {
            return SerialNumberPattern.Match(line);
        }

        public static Match GetEkuMatch(string ekuLine)
        {
            return EkuLinePattern.Match(ekuLine);
        }

        public static Match GetCaNameMatch(string output)
        {
            return CaNamePattern.Match(output);
        }

        public static Match GetEditFlagsMatch(string output)
        {
            return EditFlagsPattern.Match(output);
        }

        public static bool IsFqdnFormat(string normalizedName)
        {
            return FqdnPattern.IsMatch(normalizedName);
        }

        public static string SanitizeFileName(string name)
        {
            return FileNameSanitizePattern.Replace(name, "_");
        }

        public static string NormalizeRequestId(string id)
        {
            var hexWithDecimalMatch = RequestIdHexWithDecimalPattern.Match(id);
            if (hexWithDecimalMatch.Success)
            {
                return hexWithDecimalMatch.Groups[2].Value;
            }

            var hexMatch = RequestIdHexPattern.Match(id);
            if (hexMatch.Success)
            {
                return Convert.ToInt32(hexMatch.Groups[1].Value, 16).ToString();
            }

            if (RequestIdDecimalPattern.IsMatch(id))
            {
                return id;
            }

            return id;
        }
    }
}