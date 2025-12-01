using System;
using System.IO;
using System.Threading;
using Stelark.Core;
using Stelark.Helpers;
using Stelark.Services;

namespace Stelark.Output
{
    public static class ProgressDisplay
    {
        private static Timer? _progressTimer;
        private static ProgressTracker? _currentTracker;
        private static readonly object _lock = new object();

        public static void StartProgressDisplay(ProgressTracker tracker)
        {
            lock (_lock)
            {
                _currentTracker = tracker;
                _progressTimer = new Timer(UpdateProgressDisplay, null, TimeSpan.Zero, TimeSpan.FromSeconds(2));
            }
        }

        public static void StopProgressDisplay()
        {
            lock (_lock)
            {
                _progressTimer?.Dispose();
                _progressTimer = null;
                _currentTracker = null;
            }
        }

        private static void UpdateProgressDisplay(object? state)
        {
            // Progress display disabled for cleaner console output
            // All progress tracking is still performed for internal logging,
            // but no verbose real-time updates are displayed to the console
            return;
        }

        public static void ShowProgressComplete(string operation, int totalProcessed, TimeSpan duration)
        {
            StopProgressDisplay();

            // Progress completion messages disabled for cleaner console output
            // The completion information is still logged internally for debugging
            var rate = duration.TotalSeconds > 0 ? totalProcessed / duration.TotalSeconds : 0;

            // Clear any remaining progress display artifacts but don't show completion message
            Console.Write("\r" + new string(' ', Math.Min(Console.WindowWidth - 1, 80)));
            Console.Write("\r"); // Return cursor to start of line
        }

        private static string FormatDuration(TimeSpan duration)
        {
            if (duration.TotalDays >= 1)
                return $"{duration.Days}d {duration.Hours}h {duration.Minutes}m";
            else if (duration.TotalHours >= 1)
                return $"{duration.Hours}h {duration.Minutes}m {duration.Seconds}s";
            else if (duration.TotalMinutes >= 1)
                return $"{duration.Minutes}m {duration.Seconds}s";
            else
                return $"{duration.TotalSeconds:F1}s";
        }
    }


    public static class ConfigurationValidator
    {
        public static void ValidateConfiguration(GlobalState state)
        {
            Logger.LogInfo("Starting configuration validation");

            // Memory validation
            ValidateMemoryConfiguration(state);



            // CA connectivity validation (will be done later in Initialize)
            ValidateOutputDirectory(state);

            Logger.LogInfo("Configuration validation completed");
        }

        private static void ValidateMemoryConfiguration(GlobalState state)
        {
            var systemMemoryMB = MemoryManager.GetTotalSystemMemoryMB();
            var configuredMemoryMB = state.MaxMemoryUsageMB;

            Logger.LogInfo($"Memory configuration - System: ~{systemMemoryMB}MB, Configured: {configuredMemoryMB}MB");

            if (configuredMemoryMB > systemMemoryMB * 0.8)
            {
                ConsoleHelper.WriteWarning($"Configured memory limit ({configuredMemoryMB}MB) is high relative to system memory (~{systemMemoryMB}MB)");
                ConsoleHelper.WriteInfo("This may cause system instability in memory-constrained environments");
            }

            if (configuredMemoryMB < 1024)
            {
                ConsoleHelper.WriteWarning($"Configured memory limit ({configuredMemoryMB}MB) is very low");
                ConsoleHelper.WriteInfo("Performance may be impacted by frequent garbage collection");
            }
        }



        private static void ValidateOutputDirectory(GlobalState state)
        {
            try
            {
                // Test write permissions
                var testFile = Path.Combine(state.OutputDir, $"test_{Guid.NewGuid()}.tmp");
                Directory.CreateDirectory(state.OutputDir);
                File.WriteAllText(testFile, "test");
                File.Delete(testFile);

                Logger.LogInfo($"Output directory validation successful: {state.OutputDir}");
            }
            catch (UnauthorizedAccessException)
            {
                throw new InvalidOperationException($"Insufficient permissions to write to output directory: {state.OutputDir}");
            }
            catch (DirectoryNotFoundException)
            {
                throw new InvalidOperationException($"Output directory path is invalid: {state.OutputDir}");
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Output directory validation failed: {ex.Message}");
            }
        }

        public static void ShowConfigurationSummary(GlobalState state)
        {
            Console.WriteLine();
            ConsoleHelper.WriteInfo("=== SCAN CONFIGURATION SUMMARY ===");
            ConsoleHelper.WriteInfo($"Output Directory: {state.OutputDir}");
            ConsoleHelper.WriteInfo($"Memory Limit: {state.MaxMemoryUsageMB:N0} MB");
            ConsoleHelper.WriteInfo($"Adaptive Batch Size: {MemoryManager.CalculateAdaptiveBatchSize(state.MaxMemoryUsageMB):N0} certificates");



            Console.WriteLine();
        }
    }
}