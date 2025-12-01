using System;
using System.Globalization;

namespace Stelark.Helpers
{
    /// <summary>
    /// Helper class for parsing and validating date parameters
    /// </summary>
    public static class DateHelper
    {
        /// <summary>
        /// Parse a date string with support for multiple common formats
        /// </summary>
        /// <param name="dateString">The date string to parse</param>
        /// <param name="parsedDate">The parsed DateTime if successful</param>
        /// <returns>True if parsing was successful, false otherwise</returns>
        public static bool TryParseStartDate(string dateString, out DateTime parsedDate)
        {
            parsedDate = DateTime.MinValue;

            if (string.IsNullOrWhiteSpace(dateString))
                return false;

            // Common date formats to try
            string[] formats = {
                "yyyy-MM-dd",           // 2023-12-25
                "yyyy/MM/dd",           // 2023/12/25
                "MM/dd/yyyy",           // 12/25/2023
                "dd/MM/yyyy",           // 25/12/2023
                "MM-dd-yyyy",           // 12-25-2023
                "dd-MM-yyyy",           // 25-12-2023
                "yyyy.MM.dd",           // 2023.12.25
                "dd.MM.yyyy",           // 25.12.2023
                "MMM dd yyyy",          // Dec 25 2023
                "dd MMM yyyy",          // 25 Dec 2023
                "MMMM dd yyyy",         // December 25 2023
                "dd MMMM yyyy",         // 25 December 2023
            };

            // Try parsing with specific formats first
            foreach (var format in formats)
            {
                if (DateTime.TryParseExact(dateString.Trim(), format,
                    CultureInfo.InvariantCulture, DateTimeStyles.None, out parsedDate))
                {
                    return true;
                }
            }

            // Fallback to general parsing
            if (DateTime.TryParse(dateString.Trim(), out parsedDate))
            {
                return true;
            }

            return false;
        }

        /// <summary>
        /// Validate that a start date is reasonable
        /// </summary>
        /// <param name="startDate">The start date to validate</param>
        /// <param name="errorMessage">Error message if validation fails</param>
        /// <returns>True if date is valid, false otherwise</returns>
        public static bool ValidateStartDate(DateTime startDate, out string errorMessage)
        {
            errorMessage = string.Empty;

            // Check if date is too far in the future
            if (startDate > DateTime.Now.AddDays(1))
            {
                errorMessage = "Start date cannot be in the future";
                return false;
            }

            // Check if date is unreasonably old (before Windows 2000)
            if (startDate < new DateTime(2000, 1, 1))
            {
                errorMessage = "Start date cannot be before January 1, 2000";
                return false;
            }

            return true;
        }

        /// <summary>
        /// Format a date for display purposes
        /// </summary>
        /// <param name="date">The date to format</param>
        /// <returns>Formatted date string</returns>
        public static string FormatDateForDisplay(DateTime date)
        {
            return date.ToString("yyyy-MM-dd");
        }

        /// <summary>
        /// Get supported date format examples for help text
        /// </summary>
        /// <returns>String containing format examples</returns>
        public static string GetSupportedFormatsHelp()
        {
            return @"Supported date formats:
  YYYY-MM-DD    (e.g., 2023-12-25)
  MM/DD/YYYY    (e.g., 12/25/2023)
  DD/MM/YYYY    (e.g., 25/12/2023)
  Mon DD YYYY   (e.g., Dec 25 2023)";
        }
    }
}