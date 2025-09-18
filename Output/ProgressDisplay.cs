using System;
using System.IO;
using System.Text.Json;
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

    public static class CheckpointManager
    {
        public static void SaveCheckpoint(GlobalState state, ScanCheckpoint checkpoint)
        {
            try
            {
                if (string.IsNullOrEmpty(state.CheckpointFilePath))
                    return;

                // Ensure StartDate is preserved in checkpoint
                checkpoint.StartDate = state.StartDate;

                var json = JsonSerializer.Serialize(checkpoint, new JsonSerializerOptions
                {
                    WriteIndented = true
                });

                Directory.CreateDirectory(Path.GetDirectoryName(state.CheckpointFilePath)!);
                File.WriteAllText(state.CheckpointFilePath, json);

                var dateInfo = state.StartDate.HasValue ? $" (StartDate: {DateHelper.FormatDateForDisplay(state.StartDate.Value)})" : "";
                Logger.LogInfo($"Checkpoint saved: {checkpoint.Phase} - {checkpoint.ProcessedCount}/{checkpoint.TotalCount} processed{dateInfo}");
            }
            catch (Exception ex)
            {
                Logger.LogError("Failed to save checkpoint", ex);
            }
        }

        public static ScanCheckpoint? LoadCheckpoint(GlobalState state)
        {
            try
            {
                if (string.IsNullOrEmpty(state.CheckpointFilePath) || !File.Exists(state.CheckpointFilePath))
                    return null;

                var json = File.ReadAllText(state.CheckpointFilePath);
                var checkpoint = JsonSerializer.Deserialize<ScanCheckpoint>(json);

                if (checkpoint != null)
                {
                    // Validate StartDate consistency between current run and checkpoint
                    if (!ValidateStartDateConsistency(state.StartDate, checkpoint.StartDate))
                    {
                        Logger.LogWarning("Checkpoint StartDate mismatch - clearing checkpoint to prevent inconsistencies");
                        ConsoleHelper.WriteWarning("Cannot resume: different start-date filter detected. Starting fresh scan.");
                        ClearCheckpoint(state);
                        return null;
                    }

                    var dateInfo = checkpoint.StartDate.HasValue ? $" (StartDate: {DateHelper.FormatDateForDisplay(checkpoint.StartDate.Value)})" : "";
                    Logger.LogInfo($"Checkpoint loaded: {checkpoint.Phase} - {checkpoint.ProcessedCount}/{checkpoint.TotalCount} processed{dateInfo}");
                }

                return checkpoint;
            }
            catch (Exception ex)
            {
                Logger.LogError("Failed to load checkpoint", ex);
                ConsoleHelper.WriteWarning("Failed to load checkpoint file - starting fresh scan");
                return null;
            }
        }

        private static bool ValidateStartDateConsistency(DateTime? currentStartDate, DateTime? checkpointStartDate)
        {
            // Both null - consistent
            if (!currentStartDate.HasValue && !checkpointStartDate.HasValue)
                return true;

            // One null, one has value - inconsistent
            if (currentStartDate.HasValue != checkpointStartDate.HasValue)
                return false;

            // Both have values - must match exactly
            return currentStartDate!.Value.Date == checkpointStartDate!.Value.Date;
        }

        public static void ClearCheckpoint(GlobalState state)
        {
            try
            {
                if (!string.IsNullOrEmpty(state.CheckpointFilePath) && File.Exists(state.CheckpointFilePath))
                {
                    File.Delete(state.CheckpointFilePath);
                    Logger.LogInfo("Checkpoint file cleared");
                }
            }
            catch (Exception ex)
            {
                Logger.LogError("Failed to clear checkpoint file", ex);
            }
        }

        public static bool HasValidCheckpoint(GlobalState state)
        {
            var checkpoint = LoadCheckpoint(state);
            return checkpoint != null;
        }
    }

    public static class ConfigurationValidator
    {
        public static void ValidateConfiguration(GlobalState state)
        {
            ConsoleHelper.WriteInfo("Validating configuration...");
            Logger.LogInfo("Starting configuration validation");

            // Memory validation
            ValidateMemoryConfiguration(state);


            // Resume validation
            ValidateResumeConfiguration(state);

            // CA connectivity validation (will be done later in Initialize)
            ValidateOutputDirectory(state);

            ConsoleHelper.WriteSuccess("Configuration validation completed");
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


        private static void ValidateResumeConfiguration(GlobalState state)
        {
            if (state.ResumeMode)
            {
                if (!CheckpointManager.HasValidCheckpoint(state))
                {
                    ConsoleHelper.WriteWarning("Resume mode requested but no valid checkpoint found");
                    ConsoleHelper.WriteInfo("Scan will start from the beginning");
                    state.ResumeMode = false;
                }
                else
                {
                    ConsoleHelper.WriteSuccess("Valid checkpoint found - scan will resume from previous state");
                }
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


            if (state.ResumeMode)
            {
                ConsoleHelper.WriteInfo("Resume Mode: Enabled (will continue from last checkpoint)");
            }

            Console.WriteLine();
        }
    }
}