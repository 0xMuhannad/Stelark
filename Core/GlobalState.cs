using System;
using System.Collections.Generic;
using Stelark.Models;

namespace Stelark.Core
{
    public class GlobalState
    {
        public bool FoundCAServers { get; set; } = false;
        public bool IsLocalCAServer { get; set; } = false;
        public List<string> CAServerHostnames { get; set; } = new();
        public string OutputDir { get; set; } = string.Empty;
        public bool AllowIntenseFallback { get; set; } = false;

        // Date filtering - start date only functionality
        public DateTime? StartDate { get; set; } = null;

        // Template caching for performance
        public TemplateCache? CachedTemplates { get; set; } = null;

        // Memory management settings (enhanced for performance)
        public int BatchSize { get; set; } = 50000; // Process 50k certs at a time (adaptive batching)
        public long MaxMemoryUsageMB { get; set; } = 3072; // 3GB limit

        // Progress tracking for real-time updates
        public ProgressTracker? CurrentProgress { get; set; } = null;


        // Resume capability
        public string? CheckpointFilePath { get; set; } = null;
        public bool ResumeMode { get; set; } = false;
        public ScanCheckpoint? LastCheckpoint { get; set; } = null;

        public List<VulnerableTemplate> ESC1VulnTemplates { get; set; } = new();
        public List<VulnerableTemplate> ESC2VulnTemplates { get; set; } = new();
        public List<VulnerableTemplate> ESC3VulnTemplates { get; set; } = new();
        public List<VulnerableTemplate> ESC4VulnTemplates { get; set; } = new();
        public List<VulnerableCA> ESC6VulnCAs { get; set; } = new();
        public List<VulnerableCAPermissions> ESC7VulnCAPermissions { get; set; } = new();
        public List<VulnerableEndpoint> ESC8VulnEndpoints { get; set; } = new();

        public List<Certificate> ESC1Certificates { get; set; } = new();
        public List<Certificate> ESC2Certificates { get; set; } = new();
        public List<Certificate> ESC3Certificates { get; set; } = new();
        public List<Certificate> ESC4Certificates { get; set; } = new();
        public List<Certificate> IntenseCertificates { get; set; } = new();
        public List<Certificate> IntenseUniqueCertificates { get; set; } = new();

        public int IntenseModeProcessedCount { get; set; } = 0; // Total certificates processed in intense mode

        public int SuspiciousESC1CertCount { get; set; } = 0;
        public int SuspiciousESC2CertCount { get; set; } = 0;
        public int SuspiciousESC3CertCount { get; set; } = 0;
        public int SuspiciousESC4CertCount { get; set; } = 0;
        public int ESC6VulnCount { get; set; } = 0;
        public int ESC7VulnCount { get; set; } = 0;
        public int ESC8VulnCount { get; set; } = 0;

        public bool CertutilErrorDetected_ESC1 { get; set; } = false;
        public bool CertutilErrorDetected_ESC2 { get; set; } = false;
        public bool CertutilErrorDetected_ESC3 { get; set; } = false;
        public bool CertutilErrorDetected_ESC4 { get; set; } = false;
        public bool CertutilErrorDetected_Intense { get; set; } = false;
        public bool IntenseScanRun { get; set; } = false;

        public List<string> UnmappedTemplates { get; set; } = new();
    }

    public class ProgressTracker
    {
        public string CurrentOperation { get; set; } = string.Empty;
        public string CurrentTemplate { get; set; } = string.Empty;
        public int ProcessedCount { get; set; } = 0;
        public int TotalCount { get; set; } = 0;
        public DateTime StartTime { get; set; } = DateTime.Now;
        public DateTime LastUpdate { get; set; } = DateTime.Now;
        public double ProcessingRate { get; set; } = 0; // certificates per second
        public TimeSpan EstimatedTimeRemaining { get; set; } = TimeSpan.Zero;

        public double ProgressPercentage => TotalCount > 0 ? (double)ProcessedCount / TotalCount * 100.0 : 0;

        public void UpdateProgress(int processed, string currentItem = "")
        {
            ProcessedCount = processed;
            LastUpdate = DateTime.Now;

            if (!string.IsNullOrEmpty(currentItem))
                CurrentTemplate = currentItem;

            var elapsed = LastUpdate - StartTime;
            if (elapsed.TotalSeconds > 0)
            {
                ProcessingRate = ProcessedCount / elapsed.TotalSeconds;
                if (ProcessingRate > 0 && TotalCount > ProcessedCount)
                {
                    var remaining = TotalCount - ProcessedCount;
                    EstimatedTimeRemaining = TimeSpan.FromSeconds(remaining / ProcessingRate);
                }
            }
        }
    }

    public class ScanCheckpoint
    {
        public DateTime CheckpointTime { get; set; } = DateTime.Now;
        public string Phase { get; set; } = string.Empty;
        public int ProcessedCount { get; set; } = 0;
        public int TotalCount { get; set; } = 0;
        public List<string> CompletedTemplates { get; set; } = new();
        public string CurrentTemplate { get; set; } = string.Empty;
        public bool ESC1Complete { get; set; } = false;
        public bool ESC2Complete { get; set; } = false;
        public bool ESC3Complete { get; set; } = false;
        public bool ESC4Complete { get; set; } = false;
        public bool IntenseModeComplete { get; set; } = false;

        // Date filtering for resume consistency
        public DateTime? StartDate { get; set; } = null;
    }

    public class TemplateCache
    {
        public DateTime CacheTime { get; set; }
        public Dictionary<string, bool> PublishedTemplates { get; set; } = new();
        public List<VulnerableTemplate> ESC1Templates { get; set; } = new();
        public List<VulnerableTemplate> ESC2Templates { get; set; } = new();
        public List<VulnerableTemplate> ESC3Templates { get; set; } = new();
        public List<VulnerableTemplate> ESC4Templates { get; set; } = new();
        public bool IsValid => DateTime.Now.Subtract(CacheTime).TotalMinutes < 30; // Cache valid for 30 minutes
        public bool HasResults => ESC1Templates.Count > 0 || ESC2Templates.Count > 0 || ESC3Templates.Count > 0 || ESC4Templates.Count > 0;
    }

    public class TemplateInfo
    {
        public string DisplayName { get; set; } = string.Empty;
        public string CN { get; set; } = string.Empty;
        public string? OID { get; set; }
        public System.DirectoryServices.SearchResult Result { get; set; } = null!;
    }

    public class EnrollmentInfo
    {
        public bool HasEnroll { get; set; }
        public List<string> EnrollmentGroups { get; set; } = new();
    }
}