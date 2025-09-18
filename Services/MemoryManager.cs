using System;
using System.Diagnostics;

namespace Stelark.Services
{
    public static class MemoryManager
    {
        public static long CalculateOptimalMemoryLimitMB(int? userSpecifiedMB = null)
        {
            // Enhanced memory calculation with system awareness
            if (userSpecifiedMB.HasValue)
                return userSpecifiedMB.Value;

            // Get total system memory
            var totalSystemMemoryMB = GetTotalSystemMemoryMB();

            // Use up to 50% of system memory, but cap at 6GB for safety
            var optimalMemoryMB = Math.Min(totalSystemMemoryMB / 2, 6144);

            // Minimum 2GB, maximum 6GB
            return Math.Max(2048, Math.Min(optimalMemoryMB, 6144));
        }

        public static long GetCurrentMemoryUsageMB()
        {
            using var process = Process.GetCurrentProcess();
            return process.PrivateMemorySize64 / 1024 / 1024; // Convert to MB
        }

        public static long GetTotalSystemMemoryMB()
        {
            try
            {
                // Use GC.GetTotalMemory for more reliable memory information
                var gcInfo = GC.GetGCMemoryInfo();
                if (gcInfo.TotalAvailableMemoryBytes > 0)
                {
                    return gcInfo.TotalAvailableMemoryBytes / 1024 / 1024;
                }

                // Fallback to performance counter approach
                using var memoryInfo = new PerformanceCounter("Memory", "Available MBytes");
                var availableMemory = (long)memoryInfo.NextValue();

                // Conservative estimate with buffer
                return Math.Max(4096, availableMemory + 2048);
            }
            catch
            {
                // Fallback to safe default if all methods fail
                return 8192; // 8GB default assumption
            }
        }

        public static bool IsMemoryLimitExceeded(long maxMemoryMB)
        {
            var currentMemoryMB = GetCurrentMemoryUsageMB();
            return currentMemoryMB > maxMemoryMB;
        }

        public static int CalculateAdaptiveBatchSize(long maxMemoryMB, int certificateCount = 0)
        {
            var currentMemoryMB = GetCurrentMemoryUsageMB();
            var memoryUsageRatio = (double)currentMemoryMB / maxMemoryMB;

            // More granular adaptive sizing based on memory pressure
            if (memoryUsageRatio > 0.9)
            {
                return Math.Max(1000, 50000 / 10); // Very low memory - drastically reduce batch size
            }
            else if (memoryUsageRatio > 0.8)
            {
                return Math.Max(5000, 50000 / 4); // High memory pressure - reduce batch size
            }
            else if (memoryUsageRatio > 0.6)
            {
                return 50000; // Moderate memory usage - use default
            }
            else if (memoryUsageRatio > 0.4)
            {
                return Math.Min(75000, (int)(50000 * 1.5)); // Low memory usage - increase moderately
            }
            else
            {
                return Math.Min(100000, 50000 * 2); // Very low memory usage - increase batch size
            }
        }

        /// <summary>
        /// Calculate optimal batch size based on current GC memory pressure
        /// </summary>
        public static int CalculateOptimalBatchSize()
        {
            var gcInfo = GC.GetGCMemoryInfo();
            var memoryPressure = gcInfo.MemoryLoadBytes / (double)gcInfo.TotalAvailableMemoryBytes;

            return memoryPressure switch
            {
                > 0.9 => 1000,      // Critical memory pressure
                > 0.8 => 5000,      // High pressure
                > 0.6 => 15000,     // Medium pressure
                > 0.4 => 35000,     // Low pressure
                _ => 75000          // Normal operation
            };
        }

        /// <summary>
        /// Dynamic batch sizing that adapts to real-time memory conditions
        /// </summary>
        public static int CalculateDynamicBatchSize(int baseBatchSize, int processedCount)
        {
            var gcInfo = GC.GetGCMemoryInfo();
            var memoryPressure = gcInfo.MemoryLoadBytes / (double)gcInfo.TotalAvailableMemoryBytes;
            var heapSize = gcInfo.HeapSizeBytes / (1024.0 * 1024.0); // Convert to MB

            // Adjust based on heap fragmentation and memory pressure
            var fragmentationRatio = gcInfo.FragmentedBytes / (double)gcInfo.HeapSizeBytes;
            var pressureMultiplier = memoryPressure < 0.7 ? 1.0 : (1.0 - memoryPressure);
            var fragmentationMultiplier = fragmentationRatio < 0.2 ? 1.0 : (1.0 - fragmentationRatio);

            var adjustedSize = (int)(baseBatchSize * pressureMultiplier * fragmentationMultiplier);

            // Ensure reasonable bounds
            return Math.Max(500, Math.Min(adjustedSize, 100000));
        }

        public static void ForceGarbageCollection()
        {
            // More efficient garbage collection approach
            if (IsMemoryPressureHigh(0)) // Check if we really need to force GC
            {
                GC.Collect(GC.MaxGeneration, GCCollectionMode.Optimized, false);
                GC.WaitForPendingFinalizers();
            }
        }

        public static void LogMemoryUsage(string context)
        {
            var processMB = GetCurrentMemoryUsageMB();
            var totalSystemMB = GetTotalSystemMemoryMB();
            var memoryPressurePercent = (double)processMB / totalSystemMB * 100.0;

            Logger.LogInfo($"Memory usage at {context}: {processMB} MB ({memoryPressurePercent:F1}% of estimated system memory)");
        }

        public static bool ShouldReduceBatchSize(long maxMemoryMB)
        {
            return IsMemoryPressureHigh(maxMemoryMB);
        }

        public static bool IsMemoryPressureHigh(long maxMemoryMB)
        {
            var currentMemoryMB = GetCurrentMemoryUsageMB();
            return currentMemoryMB > maxMemoryMB * 0.75; // High pressure if using >75% of limit
        }
    }
}