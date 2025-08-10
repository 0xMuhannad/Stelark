using System;
using System.Diagnostics;

namespace Stelark
{
    public static class MemoryManager
    {
        public static long CalculateOptimalMemoryLimitMB(int? userSpecifiedMB = null)
        {
            // Simple fixed limit: certificates are small, 3GB is massive overkill for any scenario
            // 100k certificates = ~80MB, so 3GB handles 3M+ certificates easily
            return userSpecifiedMB ?? 3072; // Default 3GB - simple and more than sufficient
        }
        
        public static long GetCurrentMemoryUsageMB()
        {
            using var process = Process.GetCurrentProcess();
            return process.PrivateMemorySize64 / 1024 / 1024; // Convert to MB
        }
        
        public static bool IsMemoryLimitExceeded(long maxMemoryMB)
        {
            var currentMemoryMB = GetCurrentMemoryUsageMB();
            return currentMemoryMB > maxMemoryMB;
        }
        
        public static void ForceGarbageCollection()
        {
            GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, true);
            GC.WaitForPendingFinalizers();
        }
        
        public static void LogMemoryUsage(string context)
        {
            var processMB = GetCurrentMemoryUsageMB();
            Logger.LogInfo($"Memory usage at {context}: {processMB} MB");
        }
    }
}