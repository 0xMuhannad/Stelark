using System;
using System.Linq;
using System.Threading.Tasks;
using Stelark.Core;
using Stelark.Helpers;
using Stelark.Services;
using static Stelark.Helpers.PerformanceOptimizations;

namespace Stelark
{
    /// <summary>
    /// Stelark - Compromise Assessment Tool for Detecting ADCS Attacks
    /// Author: Muhannad Alruwais
    /// </summary>
    public class Program
    {
        private static bool _intense = false;

        public static async Task<int> Main(string[] args)
        {
            try
            {
                if (args.Any(arg => string.Equals(arg, "-h", StringComparison.OrdinalIgnoreCase) ||
                               string.Equals(arg, "--help", StringComparison.OrdinalIgnoreCase)))
                {
                    PrintHelpMessage();
                    return 0;
                }

                _intense = args.Any(arg => string.Equals(arg, "-Intense", StringComparison.OrdinalIgnoreCase) ||
                                          string.Equals(arg, "--intense", StringComparison.OrdinalIgnoreCase));
                Console.WriteLine("Stelark Compromise Assessment Tool for Detecting ADCS Attacks");
                Console.WriteLine("Author: Muhannad Alruwais");
                Console.WriteLine("The Ark that hunts the stars");
                Console.WriteLine("Version: 1.2");
                Console.WriteLine("==========================");

                // PERFORMANCE OPTIMIZATION: Initialize performance optimizations
                ConsoleHelper.WriteInfo("Initializing performance optimizations...");
                PerformanceOptimizations.WarmUpOptimizations();
                PoolStatistics.WarmUpPools();
                ConsoleHelper.WriteSuccess("Performance optimizations initialized");

                // Auto-configure memory settings (hidden from users)
                var maxMemoryMB = (int)MemoryManager.CalculateOptimalMemoryLimitMB(null);

                // Parse command-line arguments
                var outputDir = GetStringArgValue(args, "--output-dir", "");
                var resumeMode = args.Any(arg => string.Equals(arg, "--resume", StringComparison.OrdinalIgnoreCase));
                var startDateStr = GetStringArgValue(args, "--start-date", "");

                // Parse and validate start date if provided
                DateTime? startDate = null;
                if (!string.IsNullOrEmpty(startDateStr))
                {
                    if (!DateHelper.TryParseStartDate(startDateStr, out DateTime parsedStartDate))
                    {
                        ConsoleHelper.WriteError($"Invalid start date format: '{startDateStr}'");
                        Console.WriteLine();
                        Console.WriteLine(DateHelper.GetSupportedFormatsHelp());
                        return 1;
                    }

                    if (!DateHelper.ValidateStartDate(parsedStartDate, out string errorMessage))
                    {
                        ConsoleHelper.WriteError($"Invalid start date: {errorMessage}");
                        return 1;
                    }

                    startDate = parsedStartDate;
                    ConsoleHelper.WriteInfo($"Start date filter: {DateHelper.FormatDateForDisplay(parsedStartDate)} (certificates from this date onwards)");
                }


                using (var stelark = new StelarkCore(maxMemoryMB, outputDir, resumeMode, startDate))
                {
                    await stelark.RunAsync(_intense);
                }

                return 0;
            }
            catch (Exception ex)
            {
                Logger.LogError("Fatal error occurred", ex);
                ConsoleHelper.WriteError($"Fatal error: {ex.Message}");
                return 1;
            }
        }

        private static int GetArgValue(string[] args, string argName, int defaultValue)
        {
            for (int i = 0; i < args.Length - 1; i++)
            {
                if (args[i] == argName && int.TryParse(args[i + 1], out int value))
                {
                    return value;
                }
            }
            return defaultValue;
        }

        private static string GetStringArgValue(string[] args, string argName, string defaultValue)
        {
            for (int i = 0; i < args.Length - 1; i++)
            {
                if (args[i] == argName && !string.IsNullOrEmpty(args[i + 1]))
                {
                    return args[i + 1];
                }
            }
            return defaultValue;
        }

        private static void PrintHelpMessage()
        {
            Console.WriteLine("Stelark Compromise Assessment Tool for Detecting ADCS Attacks");
            Console.WriteLine("Author: Muhannad Alruwais");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("The Ark that hunts the stars.");
            Console.ResetColor();
            Console.WriteLine("Version: 1.2");
            Console.WriteLine("==============================");
            Console.WriteLine("A compromise assessment tool for detecting Active Directory Certificate Services (ADCS) attacks.");
            Console.WriteLine("\nUSAGE:");
            Console.WriteLine("  Stelark.exe [OPTIONS]");
            Console.WriteLine("\nOPTIONS:");
            Console.WriteLine("  -Intense, --intense      Runs all checks and performs a full enumeration of all issued certificates.");
            Console.WriteLine("                           This can be slow in large environments.");

            Console.WriteLine("\n  --output-dir <path>      Custom output directory for results and logs");
            Console.WriteLine("                           Default: ./Stelark (in current directory)");

            Console.WriteLine("\n  --start-date <date>      Only analyze certificates issued on or after this date");
            Console.WriteLine("                           Supported formats: YYYY-MM-DD, MM/DD/YYYY, DD/MM/YYYY, Mon DD YYYY");
            Console.WriteLine("                           Default: analyze all certificates (no date filtering)");

            Console.WriteLine("\n  --resume                 Resume an interrupted scan from the last checkpoint");
            Console.WriteLine("                           Automatically loads previous scan progress");

            Console.WriteLine("\n  -h, --help               Displays this help message.");

            Console.WriteLine("\nEXAMPLES:");
            Console.WriteLine("  # Run with custom output directory");
            Console.WriteLine("  Stelark.exe --intense --output-dir \"C:\\Stelark\\Results\"");
            Console.WriteLine("  ");
            Console.WriteLine("  # Analyze certificates issued from January 1, 2024 onwards");
            Console.WriteLine("  Stelark.exe --start-date 2024-01-01 --intense");
            Console.WriteLine("  ");
            Console.WriteLine("  # Resume an interrupted intense scan");
            Console.WriteLine("  Stelark.exe --intense --resume");
            Console.WriteLine("  ");
            Console.WriteLine("  # Run standard scan with date filter and custom output");
            Console.WriteLine("  Stelark.exe --start-date \"Dec 1 2023\" --output-dir \"C:\\Stelark\\Results\"");
            Console.WriteLine("\nBy default, with no options, the tool runs all checks except for the intense certificate enumeration.");
        }
    }
}