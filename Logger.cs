using System;
using System.IO;
using System.Text;

namespace Stelark
{
    public static class Logger
    {
        private static string? _outputDir;
        private static string? _errorLogPath;
        private static string? _outputLogPath;
        private static readonly object _lock = new object();
        private static TextWriter? _originalConsoleOut;
        private static FileStream? _outputFileStream;
        private static StreamWriter? _outputStreamWriter;
        private static TeeTextWriter? _teeWriter;

        public static void Initialize(string outputDir)
        {
            _outputDir = outputDir;
            _errorLogPath = Path.Combine(outputDir, "stelark.log");
            _outputLogPath = Path.Combine(outputDir, "output.txt");


            Directory.CreateDirectory(outputDir);

            InitializeConsoleCapture();

            LogSessionStart();
            LogInfo("Logger initialized");
            LogInfo($"Activity log: {_errorLogPath}");
            LogInfo($"Console output: {_outputLogPath}");
        }

        private static void InitializeConsoleCapture()
        {
            try
            {

                _originalConsoleOut = Console.Out;


                _outputFileStream = new FileStream(_outputLogPath!, FileMode.Create, FileAccess.Write, FileShare.Read);
                _outputStreamWriter = new StreamWriter(_outputFileStream, Encoding.UTF8) { AutoFlush = true };


                _teeWriter = new TeeTextWriter(_originalConsoleOut, _outputStreamWriter);
                Console.SetOut(_teeWriter);
            }
            catch (Exception ex)
            {

                LogError("Failed to initialize console capture", ex);
            }
        }

        public static void LogError(string message, Exception? exception = null)
        {
            lock (_lock)
            {
                if (string.IsNullOrEmpty(_errorLogPath) || _cleanupCompleted)
                    return;
                try
                {
                    var logEntry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] ERROR: {message}";
                    if (exception != null)
                    {
                        logEntry += $"\nException: {exception.GetType().Name}";
                        logEntry += $"\nMessage: {exception.Message}";
                        logEntry += $"\nStackTrace: {exception.StackTrace}";
                        if (exception.InnerException != null)
                        {
                            logEntry += $"\nInner Exception: {exception.InnerException.GetType().Name}";
                            logEntry += $"\nInner Message: {exception.InnerException.Message}";
                        }
                    }
                    logEntry += "\n" + new string('-', 80) + "\n";

                    File.AppendAllText(_errorLogPath, logEntry);

    
                    ConsoleHelper.WriteError($"{message}{(exception != null ? $" - {exception.Message}" : "")}");
                }
                catch (Exception ex)
                {
                    ConsoleHelper.WriteError($"Failed to write to error log: {message} - {ex.Message}");
                }
            }
        }

        public static void LogWarning(string message)
        {
            lock (_lock)
            {
                if (string.IsNullOrEmpty(_errorLogPath) || _cleanupCompleted)
                    return;
                try
                {
                    var logEntry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] WARNING: {message}\n";
                    File.AppendAllText(_errorLogPath, logEntry);
                }
                catch (Exception ex)
                {
                    ConsoleHelper.WriteError($"Failed to write warning to log: {ex.Message}");
                }
            }
        }

        public static void LogInfo(string message)
        {
            lock (_lock)
            {
                if (string.IsNullOrEmpty(_errorLogPath) || _cleanupCompleted)
                    return;
                try
                {
                    var logEntry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] INFO: {message}\n";
                    File.AppendAllText(_errorLogPath, logEntry);
                }
                catch (Exception ex)
                {
                    ConsoleHelper.WriteError($"Failed to write info to log: {ex.Message}");
                }
            }
        }

        public static void LogDiscovery(string item, string details)
        {
            LogInfo($"DISCOVERY: {item} - {details}");
        }

        public static void LogVulnerability(string escType, string templateName, string details)
        {
            LogInfo($"VULNERABILITY: {escType} - Template '{templateName}' - {details}");
        }

        public static void LogCertificate(string action, string requestId, string requester, string template, string status)
        {
            LogInfo($"CERTIFICATE: {action} - Request {requestId} | Requester: {requester} | Template: {template} | Status: {status}");
        }

        public static void LogPermission(string type, string principal, string target, string permission)
        {
            LogInfo($"PERMISSION: {type} - Principal '{principal}' has '{permission}' on '{target}'");
        }

        public static void LogFileOperation(string operation, string filePath, string status)
        {
            LogInfo($"FILE: {operation} - {filePath} - {status}");
        }

        public static void LogQuery(string queryType, string target, int resultCount)
        {
            LogInfo($"QUERY: {queryType} on '{target}' returned {resultCount} results");
        }

        public static void LogStatistic(string category, int count, string description)
        {
            LogInfo($"STATS: {category} = {count} ({description})");
        }

        public static void LogTemplateDecision(string templateName, string escType, bool isVulnerable, string reason)
        {
            var decision = isVulnerable ? "VULNERABLE" : "SKIPPED";
            LogInfo($"TEMPLATE_DECISION: {escType} - '{templateName}' = {decision} - {reason}");
        }

        public static void LogCertificateDecision(string requestId, string template, bool isSuspicious, string reason)
        {
            var decision = isSuspicious ? "SUSPICIOUS" : "SKIPPED";
            LogInfo($"CERT_DECISION: Request {requestId} ({template}) = {decision} - {reason}");
        }

        public static void LogTemplateAnalysis(string templateName, string property, string value, string impact, string escType = "")
        {
            var escContext = !string.IsNullOrEmpty(escType) ? $"[{escType}] " : "";
            LogInfo($"TEMPLATE_ANALYSIS: {escContext}'{templateName}' - {property}: {value} ({impact})");
        }

        public static void LogCertificateAnalysis(string requestId, string property, string value, string impact, string escType = "")
        {
            var escContext = !string.IsNullOrEmpty(escType) ? $"[{escType}] " : "";
            LogInfo($"CERT_ANALYSIS: {escContext}Request {requestId} - {property}: {value} ({impact})");
        }

        private static bool _cleanupCompleted = false;
        
        public static void Cleanup()
        {
            try
            {
                // Prevent multiple cleanup calls
                if (_cleanupCompleted)
                {
                    return;
                }

                // Log session end BEFORE disposing file streams
                LogInfo("Logger cleanup completed");
                LogSessionEnd();

                if (_originalConsoleOut != null)
                {
                    Console.SetOut(_originalConsoleOut);
                    _originalConsoleOut = null;
                }

                // Dispose file streams AFTER logging
                _teeWriter?.Dispose();
                _teeWriter = null;
                _outputStreamWriter?.Dispose();
                _outputStreamWriter = null;
                _outputFileStream?.Dispose();
                _outputFileStream = null;
                
                // Clear the error log path to prevent further writes
                _errorLogPath = null;
                _cleanupCompleted = true;
            }
            catch (Exception ex)
            {
                ConsoleHelper.WriteError($"Error during logger cleanup: {ex.Message}");
                _cleanupCompleted = true; // Mark as completed even if there was an error
            }
        }

        private static void LogSessionStart()
        {
            if (string.IsNullOrEmpty(_errorLogPath) || _cleanupCompleted)
                return;

            lock (_lock)
            {
                try
                {
                    var separator = new string('=', 80);
                    var logEntry = $"{separator}\n" +
                                   $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] SESSION START: Stelark v1.0\n" +
                                   $"{separator}\n";
                    File.AppendAllText(_errorLogPath, logEntry);
                }
                catch (Exception ex)
                {
                    ConsoleHelper.WriteError($"Failed to write session start to log: {ex.Message}");
                }
            }
        }

        private static void LogSessionEnd()
        {
            if (string.IsNullOrEmpty(_errorLogPath) || _cleanupCompleted)
                return;

            lock (_lock)
            {
                try
                {
                    var separator = new string('=', 80);
                    var logEntry = $"{separator}\n" +
                                   $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] SESSION END: Stelark scan completed\n" +
                                   $"{separator}\n\n";
                    File.AppendAllText(_errorLogPath, logEntry);
                }
                catch (Exception ex)
                {
                    ConsoleHelper.WriteError($"Failed to write session end to log: {ex.Message}");
                }
            }
        }
    }

    
    public class TeeTextWriter : TextWriter
    {
        private readonly TextWriter _writer1;
        private readonly TextWriter _writer2;

        public TeeTextWriter(TextWriter writer1, TextWriter writer2)
        {
            _writer1 = writer1;
            _writer2 = writer2;
        }

        public override Encoding Encoding => _writer1.Encoding;

        public override void Write(char value)
        {
            _writer1.Write(value);
            _writer2.Write(value);
        }

        public override void Write(string? value)
        {
            _writer1.Write(value);
            _writer2.Write(value);
        }

        public override void WriteLine()
        {
            _writer1.WriteLine();
            _writer2.WriteLine();
        }

        public override void WriteLine(string? value)
        {
            _writer1.WriteLine(value);
            _writer2.WriteLine(value);
        }

        public override void Flush()
        {
            _writer1.Flush();
            _writer2.Flush();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _writer1?.Dispose();
                _writer2?.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}