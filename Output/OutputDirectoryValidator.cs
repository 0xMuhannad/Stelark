using System;
using System.IO;
using Stelark.Services;

namespace Stelark.Output
{
    public static class OutputDirectoryValidator
    {
        public static void ValidateOutputDirectory(string outputDir)
        {
            if (string.IsNullOrEmpty(outputDir))
                throw new ArgumentException("Output directory cannot be null or empty");

            try
            {
                // Check if the path is rooted (absolute) and get full path
                var fullPath = Path.GetFullPath(outputDir);
                
                // Check if it's pointing to a file instead of directory
                if (File.Exists(fullPath))
                {
                    throw new InvalidOperationException($"Output path '{outputDir}' points to an existing file, not a directory.");
                }
                
                // Try to create the directory if it doesn't exist to test permissions
                if (!Directory.Exists(fullPath))
                {
                    var parentDir = Directory.GetParent(fullPath);
                    if (parentDir != null && !parentDir.Exists)
                    {
                        // Check if we can create the parent directories
                        try
                        {
                            parentDir.Create();
                        }
                        catch (UnauthorizedAccessException)
                        {
                            throw new InvalidOperationException($"No permission to create output directory '{outputDir}'. Check directory permissions.");
                        }
                        catch (DirectoryNotFoundException)
                        {
                            throw new InvalidOperationException($"Parent directory path for '{outputDir}' is invalid or contains invalid characters.");
                        }
                    }
                }
                
                // Test write permissions by attempting to create a temp file
                var testFile = Path.Combine(fullPath, $"stelark_write_test_{Guid.NewGuid()}.tmp");
                try
                {
                    Directory.CreateDirectory(fullPath);
                    File.WriteAllText(testFile, "test");
                    File.Delete(testFile);
                }
                catch (UnauthorizedAccessException)
                {
                    throw new InvalidOperationException($"No write permission to output directory '{outputDir}'. Check directory permissions.");
                }
                catch (DirectoryNotFoundException)
                {
                    throw new InvalidOperationException($"Output directory path '{outputDir}' is invalid or contains invalid characters.");
                }
                catch (IOException ex)
                {
                    throw new InvalidOperationException($"Cannot write to output directory '{outputDir}': {ex.Message}");
                }
            }
            catch (ArgumentException ex)
            {
                throw new InvalidOperationException($"Invalid characters in output directory path '{outputDir}': {ex.Message}");
            }
            catch (NotSupportedException ex)
            {
                throw new InvalidOperationException($"Output directory path format not supported '{outputDir}': {ex.Message}");
            }
            catch (PathTooLongException)
            {
                throw new InvalidOperationException($"Output directory path '{outputDir}' is too long. Use a shorter path.");
            }
        }
        
        public static void LogOutputDirectoryInfo(string outputDir)
        {
            try
            {
                var dirInfo = new DirectoryInfo(outputDir);
                var parentDrive = Directory.GetDirectoryRoot(outputDir);
                var driveInfo = new DriveInfo(parentDrive);
                
                Logger.LogInfo($"Output directory: {dirInfo.FullName}");
                Logger.LogInfo($"Directory exists: {dirInfo.Exists}");
                Logger.LogInfo($"Parent drive: {parentDrive}");
                Logger.LogInfo($"Available space: {FormatBytes(driveInfo.AvailableFreeSpace)}");
                Logger.LogInfo($"Total space: {FormatBytes(driveInfo.TotalSize)}");
            }
            catch (Exception ex)
            {
                Logger.LogWarning($"Could not retrieve output directory information: {ex.Message}");
            }
        }
        
        private static string FormatBytes(long bytes)
        {
            const long KB = 1024;
            const long MB = KB * 1024;
            const long GB = MB * 1024;
            const long TB = GB * 1024;
            
            if (bytes >= TB) return $"{bytes / (double)TB:F2} TB";
            if (bytes >= GB) return $"{bytes / (double)GB:F2} GB";
            if (bytes >= MB) return $"{bytes / (double)MB:F2} MB";
            if (bytes >= KB) return $"{bytes / (double)KB:F2} KB";
            return $"{bytes} bytes";
        }
    }
}
