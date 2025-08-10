using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Diagnostics;
using System.IO.Compression;
using System.ServiceProcess;

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
                Console.WriteLine("Version: 1.1");
                Console.WriteLine("==========================");

                // Auto-configure memory settings (hidden from users)
                var maxMemoryMB = (int)MemoryManager.CalculateOptimalMemoryLimitMB(null);
                
                // Parse output directory argument
                var outputDir = GetStringArgValue(args, "--output-dir", "");

                using (var stelark = new Stelark(maxMemoryMB, outputDir))
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
            Console.WriteLine("★ The Ark that hunts the stars.");
            Console.ResetColor();
            Console.WriteLine("Version: 1.1");
            Console.WriteLine("==============================");
            Console.WriteLine("A compromise assessment tool for detecting Active Directory Certificate Services (ADCS) attacks.");
            Console.WriteLine("\nUSAGE:");
            Console.WriteLine("  Stelark.exe [OPTIONS]");
            Console.WriteLine("\nOPTIONS:");
            Console.WriteLine("  -Intense, --intense      Runs all checks and performs a full enumeration of all issued certificates.");
            Console.WriteLine("                           This can be slow in large environments.");


            Console.WriteLine("\n  --output-dir <path>      Custom output directory for results and logs");
            Console.WriteLine("                           Default: ./Stelark (in current directory)");
            Console.WriteLine("\n  -h, --help               Displays this help message.");

            Console.WriteLine("\nEXAMPLES:");
            Console.WriteLine("  # Run with custom output directory");
            Console.WriteLine("  Stelark.exe --intense --output-dir \"C:\\Stelark\\Results\"");
            Console.WriteLine("  ");
            Console.WriteLine("  # Run standard scan with custom output");
            Console.WriteLine("  Stelark.exe --output-dir \"C:\\Stelark\\Results\"");
            Console.WriteLine("\nBy default, with no options, the tool runs all checks except for the intense certificate enumeration.");
        }
    }

    public class Stelark : IDisposable
    {
        private readonly GlobalState _state;
        private readonly CertificateAnalyzer _certAnalyzer;
        private readonly TemplateAnalyzer _templateAnalyzer;
        private readonly CAAnalyzer _caAnalyzer;
        private readonly OutputManager _outputManager;

        public Stelark() : this(3072, "")
        {
        }

        public Stelark(int maxMemoryMB, string customOutputDir)
        {
            _state = new GlobalState
            {
                MaxMemoryUsageMB = maxMemoryMB
            };
            
            // Set output directory - use custom if provided, otherwise default
            if (!string.IsNullOrEmpty(customOutputDir))
            {
                try
                {
                    // Validate and set custom output directory
                    _state.OutputDir = Path.GetFullPath(customOutputDir);
                    
                    // Ensure it's not a file
                    if (File.Exists(_state.OutputDir))
                    {
                        throw new InvalidOperationException($"Output path '{customOutputDir}' is a file, not a directory.");
                    }
                }
                catch (Exception ex) when (!(ex is InvalidOperationException))
                {
                    throw new InvalidOperationException($"Invalid output directory path '{customOutputDir}': {ex.Message}", ex);
                }
            }
            else
            {
                _state.OutputDir = Path.Combine(AppContext.BaseDirectory, "Stelark");
            }
            
            _certAnalyzer = new CertificateAnalyzer(_state);
            _templateAnalyzer = new TemplateAnalyzer(_state);
            _caAnalyzer = new CAAnalyzer(_state);
            _outputManager = new OutputManager(_state);
        }

        public async Task RunAsync(bool intense)
        {
            try
            {
                MemoryManager.LogMemoryUsage("startup");
                Initialize();
                
                if (_state.AllowIntenseFallback)
                {
                    if (intense)
                    {
                        await RunIntenseModeOnlyAsync();
                    }
                    else
                    {
                        ConsoleHelper.WriteWarning("To Hunt for Suspicious Certificates, Re-run with -Intense.");
                    }
                    return;
                }

                await RunFullAnalysisAsync(intense);
                
                MemoryManager.LogMemoryUsage("completion");
            }
            catch (Exception ex)
            {
                Logger.LogError("Analysis failed", ex);
                ConsoleHelper.WriteError($"Analysis failed: {ex.Message}");
                MemoryManager.LogMemoryUsage("error");
                throw;
            }
        }

        private void Initialize()
        {
            ConsoleHelper.WriteInfo("Initializing Stelark...");
            
            // Validate and create output directory
            try
            {
                OutputDirectoryValidator.ValidateOutputDirectory(_state.OutputDir);
                Directory.CreateDirectory(_state.OutputDir);
                Logger.Initialize(_state.OutputDir);
                
                ConsoleHelper.WriteSuccess($"Output directory: {_state.OutputDir}");
                Logger.LogInfo($"Output directory created: {_state.OutputDir}");
                OutputDirectoryValidator.LogOutputDirectoryInfo(_state.OutputDir);
                Logger.LogInfo($"Memory configuration - Max Memory: {_state.MaxMemoryUsageMB} MB, Batch Size: {_state.BatchSize}");
                Logger.LogInfo($"Running on: {Environment.MachineName} ({Environment.UserName})");
                Logger.LogInfo($"Operating System: {Environment.OSVersion}");
                Logger.LogInfo($"Current Directory: {Environment.CurrentDirectory}");
            }
            catch (Exception ex)
            {
                ConsoleHelper.WriteError($"Output directory error: {ex.Message}");
                throw;
            }
            
            if (!IsCertutilAvailable())
            {
                ConsoleHelper.WriteError("certutil.exe not found in PATH. This tool is required for certificate enumeration.");
                throw new InvalidOperationException("certutil.exe is a required dependency and was not found in your system's PATH.");
            }
            
            _caAnalyzer.FindCAServers();
            _caAnalyzer.TestIsLocalCAServer();
            
            // Only check for local CertSvc if no remote CA servers were found
            if (!_state.FoundCAServers && !_state.IsLocalCAServer)
            {
                Logger.LogInfo("No CA servers found via LDAP - checking for local Certificate Authority service");
                if (IsLocalCertSvcRunning())
                {
                    _state.IsLocalCAServer = true;
                    _state.AllowIntenseFallback = true;
                    ConsoleHelper.WriteSuccess("Local Certificate Authority service detected. Running in offline mode.");
                    Logger.LogInfo("Local Certificate Authority service detected. Running in offline mode.");
                }
                else
                {
                    Logger.LogInfo("No local Certificate Authority service found - no CA infrastructure available");
                }
            }
        }

        private async Task RunIntenseModeOnlyAsync()
        {
            Logger.LogInfo("Starting Intense Mode Only scan");
            _state.IntenseScanRun = true;
            await _certAnalyzer.HuntIntenseCertificatesAsync();
            _certAnalyzer.DeduplicateIntenseCertificates();
            
            _outputManager.PrintFindings(true);
            _outputManager.PrintSummary(true);
            
            Logger.LogInfo("Generating output files (CSV, JSON, HTML)");
            await _outputManager.SaveFindingsAsync(true);
            
            Logger.Cleanup();
            _outputManager.ZipOutputs();
        }

        private async Task RunFullAnalysisAsync(bool intense)
        {
            var startTime = DateTime.Now;
            Logger.LogInfo($"Starting Full Analysis (Intense: {intense})");
            Logger.LogInfo($"Target CA Servers: {string.Join(", ", _state.CAServerHostnames)}");
            Logger.LogInfo($"Local CA Server: {_state.IsLocalCAServer}");
            
            // Check if we have any CA infrastructure to analyze
            if (!_state.FoundCAServers && !_state.IsLocalCAServer)
            {
                Logger.LogInfo("No CA infrastructure detected - skipping all analysis");
                var noCATime = DateTime.Now - startTime;
                
                // Print findings (will show "No CA infrastructure detected" message)
                _outputManager.PrintFindings(intense);
                PrintNoCAAnalysisSummary(noCATime);
                
                Logger.LogInfo("Generating output files (CSV, JSON, HTML)");
                await _outputManager.SaveFindingsAsync(intense);
                
                Logger.Cleanup();
                _outputManager.ZipOutputs();
                return;
            }
            
            Logger.LogInfo("Scanning for vulnerable certificate templates");
            
            // Run template analysis sequentially to ensure reliability
            _templateAnalyzer.FindESC1VulnerableTemplates();
            _templateAnalyzer.FindESC2VulnerableTemplates();
            _templateAnalyzer.FindESC3VulnerableTemplates();
            _templateAnalyzer.FindESC4VulnerableTemplates();
            Logger.LogInfo("Template vulnerability scanning completed");
            
            // Check if any vulnerable templates were found - early exit opportunity
            var totalVulnTemplates = _state.ESC1VulnTemplates.Count + 
                                   _state.ESC2VulnTemplates.Count + 
                                   _state.ESC3VulnTemplates.Count + 
                                   _state.ESC4VulnTemplates.Count;
                                   
            if (totalVulnTemplates == 0 && !intense)
            {
                ConsoleHelper.WriteSuccess("No vulnerable certificate templates found - environment appears secure!");
                ConsoleHelper.WriteInfo("Certificate hunting skipped - no vulnerabilities to investigate");
                ConsoleHelper.WriteInfo("Use --intense flag to perform full certificate database scan anyway");
                
                Logger.LogInfo("Template scan complete - no vulnerabilities found, skipping certificate hunting");
                
                // Still run CA/endpoint scans as they don't depend on templates
                Logger.LogInfo("Scanning for vulnerable CAs and endpoints");
                _caAnalyzer.FindESC6VulnerableCA();
                _caAnalyzer.FindESC7VulnerableCA();
                await _caAnalyzer.FindESC8VulnerableEndpointsAsync();
                
                // Skip to finalization
                var endTime = DateTime.Now;
                var earlyExitTime = endTime.Subtract(startTime);
                LogFinalStatistics();
                PrintAnalysisSummary(earlyExitTime);
                await _outputManager.SaveFindingsAsync(false);
                return;
            }
            
            if (totalVulnTemplates > 0)
            {
                ConsoleHelper.WriteWarning($"Found {totalVulnTemplates} vulnerable certificate templates - certificate hunting required");
                Logger.LogInfo($"Found {totalVulnTemplates} vulnerable templates - proceeding with certificate analysis");
            }
            
            Logger.LogInfo("Scanning for vulnerable CAs and endpoints");
            _caAnalyzer.FindESC6VulnerableCA();
            _caAnalyzer.FindESC7VulnerableCA();
            await _caAnalyzer.FindESC8VulnerableEndpointsAsync();
            
            Logger.LogInfo("Hunting for suspicious certificates from vulnerable templates");
            
            // Display analysis header
            Console.WriteLine();
            ConsoleHelper.WriteInfo("Starting Certificate Analysis...");
            
            await _certAnalyzer.HuntESC1CertificatesAsync();
            await _certAnalyzer.HuntESC2CertificatesAsync();
            await _certAnalyzer.HuntESC3CertificatesAsync();
            await _certAnalyzer.HuntESC4CertificatesAsync();
            
            if (intense)
            {
                Logger.LogInfo("Running Intense Mode: full certificate enumeration");
                _state.IntenseScanRun = true;
                
                Console.WriteLine();
                ConsoleHelper.WriteInfo("Starting Intense Mode Analysis...");
                ConsoleHelper.WriteWarning("This will process ALL certificates - may take time in large environments");
                
                await _certAnalyzer.HuntIntenseCertificatesAsync();
                _certAnalyzer.DeduplicateIntenseCertificates();
                
                // Show deduplication results
                var beforeDedup = _state.IntenseCertificates.Count;
                var afterDedup = _state.IntenseUniqueCertificates.Count;
                var duplicatesRemoved = beforeDedup - afterDedup;
                if (duplicatesRemoved > 0)
                {
                    var dupText = duplicatesRemoved == 1 ? "certificate" : "certificates";
                    var uniqueText = afterDedup == 1 ? "certificate" : "certificates";
                    ConsoleHelper.WriteInfo($"Deduplication complete: {duplicatesRemoved} {dupText} already found in ESC1-4 analysis were removed");
                    ConsoleHelper.WriteSuccess($"Intense Mode Unique Results: {afterDedup} new suspicious {uniqueText} found");
                }
                else if (afterDedup > 0)
                {
                    var uniqueText = afterDedup == 1 ? "certificate" : "certificates";
                    ConsoleHelper.WriteSuccess($"Intense Mode Unique Results: {afterDedup} new suspicious {uniqueText} found (no duplicates)");
                }
            }
            
            _outputManager.PrintFindings(false);
            _outputManager.PrintSummary(false);
            
            Logger.LogInfo("Generating output files (CSV, JSON, HTML)");
            LogFinalStatistics();
            await _outputManager.SaveFindingsAsync(false);
            
            var totalTime = DateTime.Now - startTime;
            Logger.LogInfo($"Full analysis completed in {totalTime.TotalSeconds:F2} seconds");
            Logger.LogInfo($"Output files saved to: {_state.OutputDir}");
            
            // Show analysis summary with scan duration
            PrintAnalysisSummary(totalTime);
            
            Logger.Cleanup();
            _outputManager.ZipOutputs();
        }

        private void LogFinalStatistics()
        {
            Logger.LogInfo("=== FINAL ANALYSIS STATISTICS ===");
            
            Logger.LogStatistic("ESC1 Vulnerable Templates", _state.ESC1VulnTemplates.Count, "templates allowing subject supply");
            Logger.LogStatistic("ESC2 Vulnerable Templates", _state.ESC2VulnTemplates.Count, "templates with Any Purpose EKU");
            Logger.LogStatistic("ESC3 Vulnerable Templates", _state.ESC3VulnTemplates.Count, "Certificate Request Agent templates");
            Logger.LogStatistic("ESC4 Vulnerable Templates", _state.ESC4VulnTemplates.Count, "templates with dangerous DACL permissions");
            
            Logger.LogStatistic("ESC6 Vulnerable CAs", _state.ESC6VulnCAs.Count, "CAs with EDITF_ATTRIBUTESUBJECTALTNAME2");
            Logger.LogStatistic("ESC7 Dangerous Permissions", _state.ESC7VulnCAPermissions.Count, "dangerous CA permissions");
            Logger.LogStatistic("ESC8 Vulnerable Endpoints", _state.ESC8VulnEndpoints.Count, "vulnerable web endpoints");
            
            Logger.LogStatistic("Suspicious ESC1 Certificates", _state.SuspiciousESC1CertCount, "certificates with SAN from ESC1 templates");
            Logger.LogStatistic("Suspicious ESC2 Certificates", _state.SuspiciousESC2CertCount, "certificates with SAN from ESC2 templates");
            Logger.LogStatistic("Suspicious ESC3 Certificates", _state.SuspiciousESC3CertCount, "certificates with SAN from ESC3 templates");
            Logger.LogStatistic("Suspicious ESC4 Certificates", _state.SuspiciousESC4CertCount, "certificates with SAN from ESC4 templates");
            
            if (_state.IntenseScanRun)
            {
                Logger.LogStatistic("Intense Mode Certificates", _state.IntenseUniqueCertificates.Count, "unique certificates with SAN from all templates");
            }
            
            var totalVulnerableTemplates = _state.ESC1VulnTemplates.Count + _state.ESC2VulnTemplates.Count + 
                                         _state.ESC3VulnTemplates.Count + _state.ESC4VulnTemplates.Count;
            
            // Calculate total certificates analyzed - use Intense Mode total if available (it processes ALL certs)
            var totalAnalyzedCerts = _state.IntenseScanRun && _state.IntenseModeProcessedCount > 0 
                ? _state.IntenseModeProcessedCount // Use the total number processed in intense mode (complete database)
                : _state.ESC1Certificates.Count + _state.ESC2Certificates.Count + 
                  _state.ESC3Certificates.Count + _state.ESC4Certificates.Count;
                  
            var totalSuspiciousCerts = _state.SuspiciousESC1CertCount + _state.SuspiciousESC2CertCount + 
                                     _state.SuspiciousESC3CertCount + _state.SuspiciousESC4CertCount;
            
            // Add Intense Mode unique certificates to total if available
            var totalSuspiciousWithIntense = _state.IntenseScanRun 
                ? totalSuspiciousCerts + _state.IntenseUniqueCertificates.Count 
                : totalSuspiciousCerts;
            
            Logger.LogStatistic("TOTAL Vulnerable Templates", totalVulnerableTemplates, "all ESC vulnerability types");
            Logger.LogStatistic("TOTAL Certificates Analyzed", totalAnalyzedCerts, "all certificates found from vulnerable templates");
            Logger.LogStatistic("TOTAL Suspicious Certificates", totalSuspiciousWithIntense, "all suspicious certificates found including intense mode");
            
            Logger.LogInfo("=== END ANALYSIS STATISTICS ===");
        }

        private void PrintAnalysisSummary(TimeSpan scanDuration)
        {
            var totalVulnerableTemplates = _state.ESC1VulnTemplates.Count + _state.ESC2VulnTemplates.Count + 
                                         _state.ESC3VulnTemplates.Count + _state.ESC4VulnTemplates.Count;
            
            // Calculate total certificates analyzed - use Intense Mode total if available (it processes ALL certs)
            var totalAnalyzedCerts = _state.IntenseScanRun && _state.IntenseModeProcessedCount > 0 
                ? _state.IntenseModeProcessedCount // Use the total number processed in intense mode (complete database)
                : _state.ESC1Certificates.Count + _state.ESC2Certificates.Count + 
                  _state.ESC3Certificates.Count + _state.ESC4Certificates.Count;
                  
            var totalSuspiciousCerts = _state.SuspiciousESC1CertCount + _state.SuspiciousESC2CertCount + 
                                     _state.SuspiciousESC3CertCount + _state.SuspiciousESC4CertCount;

            // Format scan duration
            string durationText;
            if (scanDuration.TotalDays >= 1)
            {
                durationText = $"{scanDuration.Days}d {scanDuration.Hours}h {scanDuration.Minutes}m {scanDuration.Seconds}s";
            }
            else if (scanDuration.TotalHours >= 1)
            {
                durationText = $"{scanDuration.Hours}h {scanDuration.Minutes}m {scanDuration.Seconds}s";
            }
            else if (scanDuration.TotalMinutes >= 1)
            {
                durationText = $"{scanDuration.Minutes}m {scanDuration.Seconds}s";
            }
            else
            {
                durationText = $"{scanDuration.TotalSeconds:F1}s";
            }
            
            // Display comprehensive analysis summary to console
            Console.WriteLine();
            Console.WriteLine("==================== STELARK ANALYSIS SUMMARY ====================");
            ConsoleHelper.WriteSuccess($"Total Certificates Analyzed: {totalAnalyzedCerts:N0}");
            if (_state.IntenseScanRun)
            {
                var totalWithIntense = totalSuspiciousCerts + _state.IntenseUniqueCertificates.Count;
                ConsoleHelper.WriteSuccess($"Total Suspicious Certificates: {totalWithIntense:N0}");
            }
            else
            {
                ConsoleHelper.WriteSuccess($"Total Suspicious Certificates: {totalSuspiciousCerts:N0}");
            }
            ConsoleHelper.WriteSuccess($"Vulnerable Templates Found: {totalVulnerableTemplates:N0}");
            ConsoleHelper.WriteSuccess($"Vulnerable CAs Found: {_state.ESC6VulnCAs.Count:N0}");
            ConsoleHelper.WriteSuccess($"Dangerous CA Permissions Found: {_state.ESC7VulnCAPermissions.Count:N0}");
            ConsoleHelper.WriteSuccess($"Vulnerable Endpoints Found: {_state.ESC8VulnEndpoints.Count:N0}");

            ConsoleHelper.WriteInfo($"Scan Duration: {durationText}");
            Console.WriteLine("===================================================================");
        }
        
        private void PrintNoCAAnalysisSummary(TimeSpan scanDuration)
        {
            // Format scan duration
            string durationText;
            if (scanDuration.TotalMinutes >= 1)
            {
                durationText = $"{scanDuration.Minutes}m {scanDuration.Seconds}s";
            }
            else
            {
                durationText = $"{scanDuration.TotalSeconds:F1}s";
            }
            
            Console.WriteLine();
            Console.WriteLine("==================== STELARK ANALYSIS SUMMARY ====================");
            ConsoleHelper.WriteWarning("Analysis Status: No Certificate Authority infrastructure detected");
            ConsoleHelper.WriteInfo($"Total Certificates Analyzed: 0");
            ConsoleHelper.WriteInfo($"Total Suspicious Certificates: 0");
            ConsoleHelper.WriteInfo($"Vulnerable Templates Found: 0");
            ConsoleHelper.WriteInfo($"Vulnerable CAs Found: 0");
            ConsoleHelper.WriteInfo($"Dangerous CA Permissions Found: 0");
            ConsoleHelper.WriteInfo($"Vulnerable Endpoints Found: 0");
            ConsoleHelper.WriteInfo($"Scan Duration: {durationText}");
            ConsoleHelper.WriteInfo("Recommendation: Run on a system with Active Directory Certificate Services");
            Console.WriteLine("===================================================================");
        }

        private bool IsCertutilAvailable()
        {
            var paths = Environment.GetEnvironmentVariable("PATH");
            if (paths == null) return false;

            foreach (var path in paths.Split(Path.PathSeparator))
            {
                try
                {
                    var fullPath = Path.Combine(path, "certutil.exe");
                    if (File.Exists(fullPath))
                    {
                        return true;
                    }
                }
                catch (Exception ex)
                {
                    Logger.LogError("Failed to check path for certutil.exe", ex);
                }
            }
            return false;
        }

        private bool IsLocalCertSvcRunning()
        {
            try
            {
                using var service = new ServiceController("CertSvc");
                var isRunning = service.Status == ServiceControllerStatus.Running;
                Logger.LogInfo($"CertSvc service status: {service.Status}");
                return isRunning;
            }
            catch (Exception ex)
            {
                // CertSvc service not found - normal for non-CA machines
                Logger.LogInfo($"CertSvc service not found - {ex.Message}");
                return false;
            }
        }

        public void Dispose()
        {
            try
            {
                _caAnalyzer.Dispose();
                Logger.Cleanup();
            }
            catch (Exception ex)
            {
                Logger.LogError("Error during disposal", ex);
            }
        }
    }

    public static class ConsoleHelper
    {
        public static void WriteInfo(string message)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"[+] {message}");
            Console.ResetColor();
        }

        public static void WriteError(string message)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[!] {message}");
            Console.ResetColor();
        }

        public static void WriteWarning(string message)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"[!] {message}");
            Console.ResetColor();
        }

        public static void WriteSuccess(string message)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"[+] {message}");
            Console.ResetColor();
        }
    }
} 