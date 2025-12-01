using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.IO;
using System.Threading;
using Stelark.Core;
using Stelark.Models;
using Stelark.Helpers;
using Stelark.Services;
using Stelark.Output;

namespace Stelark.Analyzers
{
    public class CertificateAnalyzer
    {
        private readonly GlobalState _state;
        private readonly Dictionary<string, List<string>> _userGroupCache = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

        public CertificateAnalyzer(GlobalState state)
        {
            _state = state;
        }

        public async Task AnalyzeESC1CertificatesAsync()
        {
            if (!_state.IsLocalCAServer || _state.ESC1VulnTemplates.Count == 0)
                return;

            var progress = new ProgressTracker
            {
                CurrentOperation = "Analyzing ESC1 Certificates",
                TotalCount = _state.ESC1VulnTemplates.Count
            };
            _state.CurrentProgress = progress;

            _state.CertutilErrorDetected_ESC1 = false;
            var allCerts = await AnalyzeCertificatesByTemplatesAsync(_state.ESC1VulnTemplates, progress);

            allCerts = FilterCertificatesByDate(allCerts);

            _state.ESC1Certificates = allCerts;
            _state.ESC1Certificates.ForEach(c =>
            {
                c.Source = "ESC1";
                c.IsSuspicious = c.ContainsSAN;
                
                if (c.IsSuspicious && ShouldExcludeRequester(c.Requester))
                {
                    c.IsSuspicious = false;
                    Logger.LogInfo($"CERT_DECISION: [ESC1] Request {c.RequestID} ({c.TemplateName}) = EXCLUDED | Requester: {c.Requester} (in ExcludedAccounts) | SAN: {c.SANUPN}");
                }
                else
                {
                    var decision = c.IsSuspicious ? "SUSPICIOUS" : "BENIGN";
                    var sanInfo = c.ContainsSAN ? c.SANUPN : "No SAN";
                    Logger.LogInfo($"CERT_DECISION: [ESC1] Request {c.RequestID} ({c.TemplateName}) = {decision} | Requester: {c.Requester} | SAN: {sanInfo} | Status: {c.DispositionMsg}");
                }
            });
            _state.SuspiciousESC1CertCount = _state.ESC1Certificates.Count(c => c.IsSuspicious);
            
            Logger.LogQuery("Certificate Analysis", "ESC1 Templates", _state.ESC1Certificates.Count);
            Logger.LogStatistic("Total ESC1 Certificates Analyzed", _state.ESC1Certificates.Count, "certificates found from ESC1 vulnerable templates");
            Logger.LogStatistic("Suspicious ESC1 Certificates", _state.SuspiciousESC1CertCount, "certificates with Subject Alternative Names");
            
            var cert1Text = _state.ESC1Certificates.Count == 1 ? "certificate" : "certificates";
            var susp1Text = _state.SuspiciousESC1CertCount == 1 ? "certificate" : "certificates";
            ConsoleHelper.WriteInfo($"ESC1 Analysis: {_state.ESC1Certificates.Count:N0} {cert1Text} analyzed, {_state.SuspiciousESC1CertCount:N0} suspicious found");
            if (_state.SuspiciousESC1CertCount > 0)
            {
                ConsoleHelper.WriteSuccess($"  Found {_state.SuspiciousESC1CertCount} {susp1Text} with Subject Alternative Names from ESC1 templates");
            }
            
            foreach (var cert in _state.ESC1Certificates.Where(c => c.IsSuspicious))
            {
                Logger.LogCertificate("Found Suspicious", cert.RequestID, cert.Requester, cert.TemplateName,
                    $"SAN: {cert.SANUPN}, Status: {cert.DispositionMsg}");
            }
        }

        public async Task AnalyzeESC2CertificatesAsync()
        {
            if (!_state.IsLocalCAServer || _state.ESC2VulnTemplates.Count == 0)
                return;

            _state.CertutilErrorDetected_ESC2 = false;
            var allCerts = await AnalyzeCertificatesByTemplatesAsync(_state.ESC2VulnTemplates);

            allCerts = FilterCertificatesByDate(allCerts);

            _state.ESC2Certificates = allCerts;
            _state.ESC2Certificates.ForEach(c =>
            {
                c.Source = "ESC2";
                c.IsSuspicious = c.ContainsSAN;
                
                if (c.IsSuspicious && ShouldExcludeRequester(c.Requester))
                {
                    c.IsSuspicious = false;
                    Logger.LogInfo($"CERT_DECISION: [ESC2] Request {c.RequestID} ({c.TemplateName}) = EXCLUDED | Requester: {c.Requester} (in ExcludedAccounts) | SAN: {c.SANUPN}");
                }
                else
                {
                    var decision = c.IsSuspicious ? "SUSPICIOUS" : "BENIGN";
                    var sanInfo = c.ContainsSAN ? c.SANUPN : "No SAN";
                    Logger.LogInfo($"CERT_DECISION: [ESC2] Request {c.RequestID} ({c.TemplateName}) = {decision} | Requester: {c.Requester} | SAN: {sanInfo} | Status: {c.DispositionMsg}");
                }
            });
            _state.SuspiciousESC2CertCount = _state.ESC2Certificates.Count(c => c.IsSuspicious);
            
            Logger.LogStatistic("Total ESC2 Certificates Analyzed", _state.ESC2Certificates.Count, "certificates found from ESC2 vulnerable templates");
            Logger.LogStatistic("Suspicious ESC2 Certificates", _state.SuspiciousESC2CertCount, "certificates with Subject Alternative Names");
            
            var cert2Text = _state.ESC2Certificates.Count == 1 ? "certificate" : "certificates";
            var susp2Text = _state.SuspiciousESC2CertCount == 1 ? "certificate" : "certificates";
            ConsoleHelper.WriteInfo($"ESC2 Analysis: {_state.ESC2Certificates.Count:N0} {cert2Text} analyzed, {_state.SuspiciousESC2CertCount:N0} suspicious found");
            if (_state.SuspiciousESC2CertCount > 0)
            {
                ConsoleHelper.WriteSuccess($"  Found {_state.SuspiciousESC2CertCount} {susp2Text} with Subject Alternative Names from ESC2 templates");
            }
        }

        public async Task AnalyzeESC3CertificatesAsync()
        {
            if (!_state.IsLocalCAServer || _state.ESC3VulnTemplates.Count == 0)
                return;

            _state.CertutilErrorDetected_ESC3 = false;
            var allCerts = await AnalyzeCertificatesByTemplatesAsync(_state.ESC3VulnTemplates);

            allCerts = FilterCertificatesByDate(allCerts);

            _state.ESC3Certificates = allCerts;
            _state.ESC3Certificates.ForEach(c =>
            {
                c.Source = "ESC3";
                c.IsSuspicious = c.ContainsSAN;
                
                if (c.IsSuspicious && ShouldExcludeRequester(c.Requester))
                {
                    c.IsSuspicious = false;
                    Logger.LogInfo($"CERT_DECISION: [ESC3] Request {c.RequestID} ({c.TemplateName}) = EXCLUDED | Requester: {c.Requester} (in ExcludedAccounts) | SAN: {c.SANUPN}");
                }
                else
                {
                    var decision = c.IsSuspicious ? "SUSPICIOUS" : "BENIGN";
                    var sanInfo = c.ContainsSAN ? c.SANUPN : "No SAN";
                    Logger.LogInfo($"CERT_DECISION: [ESC3] Request {c.RequestID} ({c.TemplateName}) = {decision} | Requester: {c.Requester} | SAN: {sanInfo} | Status: {c.DispositionMsg}");
                }
            });
            _state.SuspiciousESC3CertCount = _state.ESC3Certificates.Count(c => c.IsSuspicious);
            
            Logger.LogStatistic("Total ESC3 Certificates Analyzed", _state.ESC3Certificates.Count, "certificates found from ESC3 vulnerable templates");
            Logger.LogStatistic("Suspicious ESC3 Certificates", _state.SuspiciousESC3CertCount, "certificates with Subject Alternative Names");
            
            var cert3Text = _state.ESC3Certificates.Count == 1 ? "certificate" : "certificates";
            var susp3Text = _state.SuspiciousESC3CertCount == 1 ? "certificate" : "certificates";
            ConsoleHelper.WriteInfo($"ESC3 Analysis: {_state.ESC3Certificates.Count:N0} {cert3Text} analyzed, {_state.SuspiciousESC3CertCount:N0} suspicious found");
            if (_state.SuspiciousESC3CertCount > 0)
            {
                ConsoleHelper.WriteSuccess($"  Found {_state.SuspiciousESC3CertCount} {susp3Text} with Subject Alternative Names from ESC3 templates");
            }
        }

        public async Task AnalyzeESC4CertificatesAsync()
        {
            if (!_state.IsLocalCAServer || _state.ESC4VulnTemplates.Count == 0)
                return;

            _state.CertutilErrorDetected_ESC4 = false;
            var allCerts = await AnalyzeCertificatesByTemplatesAsync(_state.ESC4VulnTemplates);

            allCerts = FilterCertificatesByDate(allCerts);

            _state.ESC4Certificates = allCerts;
            _state.ESC4Certificates.ForEach(c =>
            {
                c.Source = "ESC4";
                c.IsSuspicious = c.ContainsSAN;
                
                if (c.IsSuspicious && ShouldExcludeRequester(c.Requester))
                {
                    c.IsSuspicious = false;
                    Logger.LogInfo($"CERT_DECISION: [ESC4] Request {c.RequestID} ({c.TemplateName}) = EXCLUDED | Requester: {c.Requester} (in ExcludedAccounts) | SAN: {c.SANUPN}");
                }
                else
                {
                    var decision = c.IsSuspicious ? "SUSPICIOUS" : "BENIGN";
                    var sanInfo = c.ContainsSAN ? c.SANUPN : "No SAN";
                    Logger.LogInfo($"CERT_DECISION: [ESC4] Request {c.RequestID} ({c.TemplateName}) = {decision} | Requester: {c.Requester} | SAN: {sanInfo} | Status: {c.DispositionMsg}");
                }
            });
            _state.SuspiciousESC4CertCount = _state.ESC4Certificates.Count(c => c.IsSuspicious);
            
            Logger.LogStatistic("Total ESC4 Certificates Analyzed", _state.ESC4Certificates.Count, "certificates found from ESC4 vulnerable templates");
            Logger.LogStatistic("Suspicious ESC4 Certificates", _state.SuspiciousESC4CertCount, "certificates with Subject Alternative Names");
            
            var cert4Text = _state.ESC4Certificates.Count == 1 ? "certificate" : "certificates";
            var susp4Text = _state.SuspiciousESC4CertCount == 1 ? "certificate" : "certificates";
            ConsoleHelper.WriteInfo($"ESC4 Analysis: {_state.ESC4Certificates.Count:N0} {cert4Text} analyzed, {_state.SuspiciousESC4CertCount:N0} suspicious found");
            if (_state.SuspiciousESC4CertCount > 0)
            {
                ConsoleHelper.WriteSuccess($"  Found {_state.SuspiciousESC4CertCount} {susp4Text} with Subject Alternative Names from ESC4 templates");
            }
        }

        public async Task AnalyzeIntenseCertificatesAsync()
        {
            if (!_state.IsLocalCAServer && !_state.AllowIntenseFallback)
                return;

            ConsoleHelper.WriteInfo("Running intense mode: full certificate enumeration (this may take a while)...");

            _state.CertutilErrorDetected_Intense = false;
            
            try
            {
                MemoryManager.LogMemoryUsage("before intense enumeration");
                
                var intenseCerts = new List<Certificate>();
                var totalProcessed = await ProcessCertificatesInBatchesAsync(intenseCerts);

                intenseCerts = FilterCertificatesByDate(intenseCerts);

                _state.IntenseCertificates = intenseCerts;
                _state.IntenseModeProcessedCount = totalProcessed;
                
                MemoryManager.LogMemoryUsage("after intense enumeration");
                Logger.LogStatistic("Intense Mode Certificates Processed", totalProcessed, "total certificates analyzed in intense mode");
                Logger.LogStatistic("Intense Mode Suspicious Certificates", intenseCerts.Count, "suspicious certificates found in intense mode");
                
                var totalText = totalProcessed == 1 ? "certificate" : "certificates";
                var suspText = intenseCerts.Count == 1 ? "certificate" : "certificates";
                ConsoleHelper.WriteInfo($"Intense Mode Analysis: {totalProcessed:N0} {totalText} processed, {intenseCerts.Count:N0} suspicious found");
                if (intenseCerts.Count > 0)
                {
                    ConsoleHelper.WriteSuccess($"  Discovered {intenseCerts.Count} {suspText} with Subject Alternative Names across all templates");
                    ConsoleHelper.WriteInfo($"  Note: Results will be deduplicated against ESC1-4 findings to show only unique certificates");
                }
            }
            catch (Exception ex)
            {
                Logger.LogError($"Failed to run intense certificate enumeration (processed {_state.IntenseModeProcessedCount} certificates before error)", ex);
                ConsoleHelper.WriteError($"Failed to run intense certificate enumeration: {ex.Message}");
                _state.CertutilErrorDetected_Intense = true;
            }
        }

        private async Task<int> ProcessCertificatesInBatchesAsync(List<Certificate> intenseCerts)
        {
            InitializeFastLookups();
            
            var currentBlock = new List<string>();
            var totalCertificatesProcessed = 0;
            var batchCount = 0;
            
            var skippedNoSAN = 0;
            var skippedAlreadyAnalyzed = 0;
            var skippedAlreadyReported = 0;
            var fullParsed = 0;
            
            await foreach (var line in StreamCertutilViewAsync())
            {
                if (RegexHelper.IsRowStart(line))
                {
                    if (currentBlock.Count > 0)
                    {
                        totalCertificatesProcessed++;
                        
                        if (!HasSANInBlock(currentBlock))
                        {
                            skippedNoSAN++;
                            currentBlock.Clear();
                            continue;
                        }
                        
                        var templateName = ExtractTemplateNameFromBlock(currentBlock);
                        if (IsTemplateVulnerable(templateName))
                        {
                            skippedAlreadyAnalyzed++;
                            currentBlock.Clear();
                            continue;
                        }
                        
                        var requestId = ExtractRequestIDFromBlock(currentBlock);
                        if (IsAlreadyReported(requestId))
                        {
                            skippedAlreadyReported++;
                            currentBlock.Clear();
                            continue;
                        }
                        
                        fullParsed++;
                        var certObj = ParseCertutilCertBlock(currentBlock);
                        if (certObj != null && !string.IsNullOrEmpty(certObj.RequestID) && certObj.IsSuspicious)
                        {
                            if (ShouldExcludeRequester(certObj.Requester))
                            {
                                Logger.LogInfo($"Certificate Request {certObj.RequestID} excluded: requester '{certObj.Requester}' is in ExcludedAccounts list");
                                currentBlock.Clear();
                                continue;
                            }
                            
                            certObj.RequestID = certObj.RequestID.NormalizeRequestID();
                            certObj.RawCertutilBlock = string.Join("\n", currentBlock);
                            certObj.Source = "INTENSE";
                            intenseCerts.Add(certObj);
                        }
                        
                        var dynamicBatchSize = MemoryManager.CalculateDynamicBatchSize(_state.BatchSize, totalCertificatesProcessed);
                        if (totalCertificatesProcessed % dynamicBatchSize == 0)
                        {
                            batchCount++;
                            Logger.LogInfo($"Processed batch {batchCount} ({totalCertificatesProcessed} certificates total, {intenseCerts.Count} suspicious, batch size: {dynamicBatchSize})");

                            if (MemoryManager.IsMemoryPressureHigh(_state.MaxMemoryUsageMB))
                            {
                                MemoryManager.ForceGarbageCollection(_state.MaxMemoryUsageMB);
                                Logger.LogInfo($"Memory pressure detected, forced garbage collection at batch {batchCount}");
                            }
                        }
                    }
                    currentBlock.Clear();
                }
                currentBlock.Add(line);
            }
            if (currentBlock.Count > 0)
            {
                totalCertificatesProcessed++;
                
                if (HasSANInBlock(currentBlock))
                {
                    var templateName = ExtractTemplateNameFromBlock(currentBlock);
                    if (!IsTemplateVulnerable(templateName))
                    {
                        var requestId = ExtractRequestIDFromBlock(currentBlock);
                        if (!IsAlreadyReported(requestId))
                        {
                            fullParsed++;
                            var certObj = ParseCertutilCertBlock(currentBlock);
                            if (certObj != null && !string.IsNullOrEmpty(certObj.RequestID) && certObj.IsSuspicious)
                            {
                                if (ShouldExcludeRequester(certObj.Requester))
                                {
                                    Logger.LogInfo($"Certificate Request {certObj.RequestID} excluded: requester '{certObj.Requester}' is in ExcludedAccounts list");
                                }
                                else
                                {
                                    certObj.RequestID = certObj.RequestID.NormalizeRequestID();
                                    certObj.RawCertutilBlock = string.Join("\n", currentBlock);
                                    certObj.Source = "INTENSE";
                                    intenseCerts.Add(certObj);
                                }
                            }
                        }
                        else
                        {
                            skippedAlreadyReported++;
                        }
                    }
                    else
                    {
                        skippedAlreadyAnalyzed++;
                    }
                }
                else
                {
                    skippedNoSAN++;
                }
            }

            var totalSkipped = skippedNoSAN + skippedAlreadyAnalyzed + skippedAlreadyReported;
            var skipPercentage = totalCertificatesProcessed > 0 ? (totalSkipped * 100.0 / totalCertificatesProcessed) : 0;
            
            Logger.LogInfo($"Fast Detection Performance: {skipPercentage:F1}% certificates skipped without full parsing");
            Logger.LogInfo($"  - No SAN: {skippedNoSAN:N0} certificates");
            Logger.LogInfo($"  - Already analyzed templates: {skippedAlreadyAnalyzed:N0} certificates");
            Logger.LogInfo($"  - Already reported: {skippedAlreadyReported:N0} certificates");
            Logger.LogInfo($"  - Full parsing for historical analysis: {fullParsed:N0} certificates");
            
            return totalCertificatesProcessed;
        }

        public void DeduplicateIntenseCertificates()
        {
            if (_state.IntenseCertificates.Count == 0)
                return;

            var reportedIDs = new HashSet<string>();

            foreach (var cert in _state.ESC1Certificates)
            {
                reportedIDs.Add(cert.RequestID.NormalizeRequestID());
            }

            foreach (var cert in _state.ESC2Certificates)
            {
                reportedIDs.Add(cert.RequestID.NormalizeRequestID());
            }

            foreach (var cert in _state.ESC3Certificates)
            {
                reportedIDs.Add(cert.RequestID.NormalizeRequestID());
            }

            foreach (var cert in _state.ESC4Certificates)
            {
                reportedIDs.Add(cert.RequestID.NormalizeRequestID());
            }

            _state.IntenseUniqueCertificates = _state.IntenseCertificates
                .Where(cert => !reportedIDs.Contains(cert.RequestID.NormalizeRequestID()))
                .ToList();
        }

        private async Task<List<Certificate>> AnalyzeCertificatesByTemplatesAsync(List<VulnerableTemplate> templates, ProgressTracker? progress = null)
        {
            var allFoundCerts = new List<Certificate>();
            var templateLookup = BuildTemplateLookup(templates);
            var vulnerabilityType = templates.FirstOrDefault()?.VulnerabilityType;

            MemoryManager.LogMemoryUsage($"before analyzing {vulnerabilityType} certificates");

            var templateIndex = 0;
            foreach (var template in templates)
            {
                try
                {
                    progress?.UpdateProgress(templateIndex, template.DisplayName);
                    templateIndex++;

                    var certs = await FindCertificatesByTemplateAsync(template.DisplayName, template.OID, templateLookup, vulnerabilityType);

                    var filteredCerts = certs.Where(cert =>
                        cert.TemplateName == template.DisplayName ||
                        cert.Template == template.CN ||
                        cert.TemplateOID == template.OID ||
                        cert.Template == template.DisplayName ||
                        cert.TemplateName == template.CN ||
                        cert.Template == template.OID
                    );

                    allFoundCerts.AddRange(filteredCerts);


                }
                catch (Exception ex)
                {
                    Logger.LogError($"Failed to analyze certificates for template {template.DisplayName}", ex);
                    ConsoleHelper.WriteError($"Failed to analyze certificates for template {template.DisplayName}: {ex.Message}");
                }
            }

            var deduplicatedCerts = allFoundCerts.GroupBy(c => new { c.Serial, c.RequestID })
                                                 .Select(g => g.First())
                                                 .ToList();

            MemoryManager.LogMemoryUsage($"after analyzing {vulnerabilityType} certificates");
            Logger.LogInfo($"Found {deduplicatedCerts.Count} unique certificates for {vulnerabilityType} templates");

            return deduplicatedCerts;
        }

        private async Task<List<Certificate>> FindCertificatesByTemplateAsync(
            string templateDisplayName,
            string? templateOID,
            Dictionary<string, VulnerableTemplate> templateLookup,
            string? vulnerabilityType)
        {
            var certutilOutputs = new List<string>();
            var queried = false;

            if (!string.IsNullOrEmpty(templateDisplayName))
            {
                var result = await RunCertutilRestrictAsync($"Certificate Template={templateDisplayName}");
                certutilOutputs.AddRange(result);
                queried = true;
            }

            if (!string.IsNullOrEmpty(templateOID))
            {
                var result = await RunCertutilRestrictAsync($"Certificate Template={templateOID}");
                certutilOutputs.AddRange(result);
                queried = true;
            }

            if (!queried)
                return new List<Certificate>();

            if (certutilOutputs.Any(line => line.StartsWith("CertUtil:")))
            {
                switch (vulnerabilityType)
                {
                    case "ESC1":
                        _state.CertutilErrorDetected_ESC1 = true;
                        break;
                    case "ESC2":
                        _state.CertutilErrorDetected_ESC2 = true;
                        break;
                    case "ESC3":
                        _state.CertutilErrorDetected_ESC3 = true;
                        break;
                    case "ESC4":
                        _state.CertutilErrorDetected_ESC4 = true;
                        break;
                }
            }

            var parsedCerts = new List<Certificate>();
            var currentBlock = new List<string>();
            
            var totalProcessed = 0;
            var skippedNoSAN = 0;
            var fullParsed = 0;

            foreach (var line in certutilOutputs)
            {
                if (RegexHelper.IsRowStart(line))
                {
                    if (currentBlock.Count > 0)
                    {
                        totalProcessed++;
                        
                        if (!HasSANInBlock(currentBlock))
                        {
                            skippedNoSAN++;
                            currentBlock.Clear();
                            continue;
                        }
                        
                        fullParsed++;
                        var certObj = ParseCertutilCertBlock(currentBlock);
                        if (certObj != null)
                        {
                            certObj.RawCertutilBlock = string.Join("\n", currentBlock);
                            ProcessCertificateTemplate(certObj, templateLookup);
                            parsedCerts.Add(certObj);
                        }
                    }
                    currentBlock.Clear();
                }
                currentBlock.Add(line);
            }

            if (currentBlock.Count > 0)
            {
                totalProcessed++;
                
                if (HasSANInBlock(currentBlock))
                {
                    fullParsed++;
                    var certObj = ParseCertutilCertBlock(currentBlock);
                    if (certObj != null)
                    {
                        certObj.RawCertutilBlock = string.Join("\n", currentBlock);
                        ProcessCertificateTemplate(certObj, templateLookup);
                        parsedCerts.Add(certObj);
                    }
                }
                else
                {
                    skippedNoSAN++;
                }
            }
            
            if (totalProcessed > 0)
            {
                var skipPercentage = (skippedNoSAN * 100.0 / totalProcessed);
                Logger.LogInfo($"Template {templateDisplayName}: {skipPercentage:F1}% certificates skipped without parsing ({skippedNoSAN:N0} of {totalProcessed:N0})");
            }

            return parsedCerts;
        }

        private void ProcessCertificateTemplate(Certificate certObj, Dictionary<string, VulnerableTemplate> templateLookup)
        {
            certObj.RequestID = certObj.RequestID.NormalizeRequestID();

            VulnerableTemplate? resolvedTemplate = null;
            string? oid = null;

            if (!string.IsNullOrEmpty(certObj.TemplateName) && templateLookup.ContainsKey(certObj.TemplateName))
            {
                resolvedTemplate = templateLookup[certObj.TemplateName];
            }
            else if (!string.IsNullOrEmpty(certObj.Template) && templateLookup.ContainsKey(certObj.Template))
            {
                resolvedTemplate = templateLookup[certObj.Template];
            }
            else if (!string.IsNullOrEmpty(certObj.TemplateName) && 
                     RegexHelper.IsOidFormat(certObj.TemplateName) && 
                     templateLookup.ContainsKey(certObj.TemplateName))
            {
                resolvedTemplate = templateLookup[certObj.TemplateName];
            }

            if (resolvedTemplate != null)
            {
                oid = resolvedTemplate.OID;
                certObj.TemplateOID = oid ?? "N/A";
                certObj.TemplateName = resolvedTemplate.DisplayName;
                certObj.Template = resolvedTemplate.CN;
            }
            else
            {
                var unmapped = certObj.TemplateName;
                if (string.IsNullOrEmpty(unmapped))
                    unmapped = certObj.Template;
                if (string.IsNullOrEmpty(unmapped))
                    unmapped = certObj.TemplateOID;

                if (!string.IsNullOrEmpty(unmapped) && unmapped != "N/A" && 
                    !_state.UnmappedTemplates.Contains(unmapped))
                {
                    _state.UnmappedTemplates.Add(unmapped);
                }
            }

            certObj.TemplateOID = oid ?? "N/A";
        }

        private Certificate? ParseCertutilCertBlock(List<string> block)
        {
            var text = string.Join("\n", block);
            var cert = new Certificate();

            if (TryExtractMatch(text, @"Request ID: ""?([^""\r\n]+)""?", out var requestId))
                cert.RequestID = requestId;

            if (TryExtractMatch(text, @"Requester Name: ""?([^""\r\n]+)""?", out var requester))
                cert.Requester = requester;

            if (TryExtractMatch(text, @"Certificate Template: ""([^""]+)""", out var templateName))
            {
                cert.TemplateName = templateName.Trim();
            }
            else if (TryExtractMatch(text, @"Certificate Template: ([^\s(]+)\s+\(([^)]+)\)", out var templateMatch))
            {
                cert.TemplateName = templateMatch.Trim();
                if (TryExtractMatch(text, @"Certificate Template: [^\s(]+\s+\(([^)]+)\)", out var oidMatch))
                    cert.TemplateOID = oidMatch.Trim();
            }
            else if (TryExtractMatch(text, @"Certificate Template: ([^\r\n]+)", out var templateGeneric))
            {
                    cert.TemplateName = templateGeneric.Trim();
            }

            var lines = text.Split('\n');
            for (int i = 0; i < lines.Length; i++)
            {
                if (lines[i].Contains("Certificate Template Name (Certificate Type)"))
                {
                    if (i + 1 < lines.Length)
                    {
                        var foundName = lines[i + 1].Trim();
                        if (!string.IsNullOrEmpty(foundName))
                        {
                            cert.TemplateName = foundName;
                            break;
                        }
                    }
                }
            }

            if (string.IsNullOrEmpty(cert.TemplateName) || 
                RegexHelper.IsOidFormat(cert.TemplateName))
            {
                if (TryExtractMatch(text, @"Request Attributes:.*CertificateTemplate:([^\s\r\n""]+)", out var attrTemplate))
                {
                    cert.TemplateName = attrTemplate;
                }
                else if (TryExtractMatch(text, @"(?m)^\s+CertificateTemplate: ""([^""]+)""", out var quotedTemplate))
                {
                    if (!RegexHelper.IsOidFormat(quotedTemplate))
                    {
                        cert.TemplateName = quotedTemplate.Trim();
                    }
                }
            }

            cert.Template = cert.TemplateName;

            if (TryExtractMatch(text, @"Request Disposition Message: ""?([^""\r\n]+)""?", out var disposition))
                cert.DispositionMsg = disposition;

            if (TryExtractMatch(text, @"Request Submission Date: ([^\r\n]+)", out var submission))
                cert.SubmissionDate = submission.Trim();

            if (TryExtractMatch(text, @"Certificate Effective Date: ([^\r\n]+)", out var effective))
                cert.NotBefore = effective.Trim();

            if (TryExtractMatch(text, @"Certificate Expiration Date: ([^\r\n]+)", out var expiration))
                cert.NotAfter = expiration.Trim();
            
            var serialLines = lines.Where(l => l.Trim().StartsWith("Serial Number:"));
            foreach (var line in serialLines)
            {
                var match = RegexHelper.GetSerialNumberMatch(line);
                if (match.Success)
                {
                    var serialValue = match.Groups[1].Value.Trim();
                    if (!string.IsNullOrEmpty(serialValue) && !serialValue.Equals("EMPTY", StringComparison.OrdinalIgnoreCase))
                    {
                        cert.Serial = serialValue;
                        break;
                    }
                }
            }

            if (TryExtractMatch(text, @"Certificate Hash: ""?([0-9a-fA-F ]{20,})""?", out var hash))
                cert.CertHash = hash.Trim();

            ParseSubjectAlternativeNames(cert, text);
            ParseClientInformation(cert, text);
            cert.EKUs = ParseEKUs(text);

            foreach (var prop in typeof(Certificate).GetProperties())
            {
                if (prop.PropertyType == typeof(string))
                {
                    var value = prop.GetValue(cert) as string;
                    if (string.IsNullOrEmpty(value) || value == "EMPTY")
                    {
                        prop.SetValue(cert, "N/A");
                    }
                }
            }

            return cert;
        }

        private List<string> ParseEKUs(string text)
        {
            var ekus = new List<string>();
            var lines = text.Split('\n');

            for (int i = 0; i < lines.Length; i++)
            {
                var line = lines[i];
                if (RegexHelper.IsEnhancedKeyUsage(line))
                {
                    int j = i + 1;
                    while (j < lines.Length && RegexHelper.IsWhitespaceLine(lines[j]))
                    {
                        var ekuLine = lines[j].Trim();
                        
                        if (ekuLine.StartsWith("[") || ekuLine.StartsWith("Policy Identifier="))
                        {
                            j++;
                            continue;
                        }
                        
                        var match = RegexHelper.GetEkuMatch(ekuLine);
                        if (match.Success)
                        {
                            var ekuName = match.Groups[1].Success ? match.Groups[1].Value.Trim() : "";
                            var ekuOID = match.Groups[2].Success ? match.Groups[2].Value.Trim() : "";
                            
                            if (!string.IsNullOrEmpty(ekuOID) && ekuOID.Contains('.'))
                            {
                                if (!string.IsNullOrEmpty(ekuName))
                                {
                                    ekus.Add($"{ekuName} ({ekuOID})");
                                }
                                else
                                {
                                    ekus.Add(ekuOID);
                                }
                            }
                        }
                        j++;
                    }
                }
            }

            return ekus;
        }

        private bool TryExtractMatch(string text, string pattern, out string result)
        {
            var match = Regex.Match(text, pattern);
            if (match.Success && match.Groups.Count > 1)
            {
                result = match.Groups[1].Value;
                return true;
            }
            result = "";
            return false;
        }

        private bool ShouldExcludeRequester(string? requester)
        {
            if (string.IsNullOrEmpty(requester))
                return false;

            var normalizedRequester = requester.ToLower().Trim();
            
            foreach (var excludedGroup in Constants.ExcludedGroups)
            {
                if (string.IsNullOrEmpty(excludedGroup))
                    continue;

                var normalizedExcluded = excludedGroup.ToLower().Trim();
                
                if (normalizedRequester.Equals(normalizedExcluded, StringComparison.OrdinalIgnoreCase) ||
                    normalizedRequester.EndsWith($"\\{normalizedExcluded}", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            foreach (var excludedUser in Constants.ExcludedUsers)
            {
                if (string.IsNullOrEmpty(excludedUser))
                    continue;

                var normalizedExcluded = excludedUser.ToLower().Trim();
                
                if (normalizedRequester.Equals(normalizedExcluded, StringComparison.OrdinalIgnoreCase) ||
                    normalizedRequester.EndsWith($"\\{normalizedExcluded}", StringComparison.OrdinalIgnoreCase) ||
                    normalizedRequester.Contains($"@{normalizedExcluded}", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            var username = ExtractUsernameFromRequester(requester);
            if (!string.IsNullOrEmpty(username))
            {
                try
                {
                    List<string> userGroups;
                    
                    if (_userGroupCache.TryGetValue(username, out var cachedGroups))
                    {
                        Core.PerformanceMetrics.IncrementGroupMembershipQuery(true);
                        userGroups = cachedGroups;
                    }
                    else
                    {
                        userGroups = GetUserGroupMemberships(username);
                        _userGroupCache[username] = userGroups;
                        Core.PerformanceMetrics.IncrementGroupMembershipQuery(false);
                    }
                    
                    foreach (var group in userGroups)
                    {
                        foreach (var excludedGroup in Constants.ExcludedGroups)
                        {
                            if (string.IsNullOrEmpty(excludedGroup))
                                continue;

                            var normalizedExcluded = excludedGroup.ToLower().Trim();
                            var normalizedGroup = group.ToLower().Trim();
                            
                            if (normalizedGroup.Equals(normalizedExcluded, StringComparison.OrdinalIgnoreCase) ||
                                normalizedGroup.EndsWith($"\\{normalizedExcluded}", StringComparison.OrdinalIgnoreCase))
                            {
                                Logger.LogInfo($"Certificate requester '{requester}' excluded: user '{username}' belongs to excluded group '{group}'");
                                return true;
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Logger.LogError($"Failed to check group memberships for requester '{requester}'", ex);
                }
            }

            return false;
        }

        private string ExtractUsernameFromRequester(string requester)
        {
            try
            {
                if (requester.Contains("\\"))
                {
                    var parts = requester.Split('\\');
                    return parts.Length > 1 ? parts[1].Trim() : requester.Trim();
                }
                else if (requester.Contains("@"))
                {
                    var parts = requester.Split('@');
                    return parts.Length > 0 ? parts[0].Trim() : requester.Trim();
                }
                else
                {
                    return requester.Trim();
                }
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error extracting username from requester '{requester}'", ex);
                return requester?.Trim() ?? string.Empty;
            }
        }


        private bool IsSuspiciousCert(Certificate cert)
        {
            if (cert.IsSuspicious)
                return true;
                
            return cert.ContainsSAN;
        }

        private Dictionary<string, VulnerableTemplate> BuildTemplateLookup(List<VulnerableTemplate> templates)
        {
            var lookup = new Dictionary<string, VulnerableTemplate>();
            
            foreach (var template in templates)
            {
                lookup[template.DisplayName] = template;
                lookup[template.CN] = template;
                if (!string.IsNullOrEmpty(template.OID))
                    lookup[template.OID] = template;
            }

            return lookup;
        }

        private bool HasSANInBlock(List<string> block)
        {
            foreach (var line in block)
            {
                if (line.Contains("SAN:upn=") || line.Contains("upn="))
                {
                    return true;
                }
            }
            return false;
        }

        private string? ExtractTemplateNameFromBlock(List<string> block)
        {
            foreach (var line in block)
            {
                if (line.Contains("Certificate Template:"))
                {
                    if (TryExtractMatch(line, @"Certificate Template: ""([^""]+)""", out var templateName))
                    {
                        return templateName.Trim();
                    }
                    else if (TryExtractMatch(line, @"Certificate Template: ([^\s(]+)", out var templateMatch))
                    {
                        return templateMatch.Trim();
                    }
                }
            }
            return null;
        }

        private string? ExtractRequestIDFromBlock(List<string> block)
        {
            foreach (var line in block)
            {
                if (line.Contains("Request ID:"))
                {
                    if (TryExtractMatch(line, @"Request ID: ""?([^""\r\n]+)""?", out var requestId))
                    {
                        return requestId.NormalizeRequestID();
                    }
                }
            }
            return null;
        }

        private HashSet<string>? _vulnerableTemplateNames;
        private HashSet<string>? _reportedRequestIds;

        private void InitializeFastLookups()
        {
            _vulnerableTemplateNames = new HashSet<string>();
            foreach (var template in _state.ESC1VulnTemplates.Concat(_state.ESC2VulnTemplates)
                                           .Concat(_state.ESC3VulnTemplates).Concat(_state.ESC4VulnTemplates))
            {
                _vulnerableTemplateNames.Add(template.DisplayName);
                _vulnerableTemplateNames.Add(template.CN);
                if (!string.IsNullOrEmpty(template.OID))
                    _vulnerableTemplateNames.Add(template.OID);
            }

            _reportedRequestIds = new HashSet<string>();
            foreach (var cert in _state.ESC1Certificates.Concat(_state.ESC2Certificates)
                                      .Concat(_state.ESC3Certificates).Concat(_state.ESC4Certificates))
            {
                if (!string.IsNullOrEmpty(cert.RequestID))
                    _reportedRequestIds.Add(cert.RequestID);
            }
        }

        private bool IsTemplateVulnerable(string? templateName)
        {
            if (string.IsNullOrEmpty(templateName) || _vulnerableTemplateNames == null)
                return false;

            return _vulnerableTemplateNames.Contains(templateName);
        }

        private bool IsAlreadyReported(string? requestId)
        {
            if (string.IsNullOrEmpty(requestId) || _reportedRequestIds == null)
                return false;

            return _reportedRequestIds.Contains(requestId);
        }

        private async IAsyncEnumerable<string> StreamCertutilViewAsync()
        {
            await foreach (var line in StreamCertutilAsync("-v -view"))
            {
                yield return line;
            }
        }

        private async Task<List<string>> RunCertutilViewAsync()
        {
            return await RunCertutilAsync("-v -view");
        }

        private async Task<List<string>> RunCertutilRestrictAsync(string restriction)
        {
            return await RunCertutilAsync($"-view -restrict \"{restriction}\"");
        }

        private async IAsyncEnumerable<string> StreamCertutilAsync(string arguments)
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "certutil.exe",
                    Arguments = arguments,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            var errorOutput = new List<string>();
            using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(30)); // Extended timeout for streaming

            process.ErrorDataReceived += (sender, args) => { if (args.Data != null) errorOutput.Add(args.Data); };

            Process startedProcess;
            try
            {
                process.Start();
                process.BeginErrorReadLine();
                startedProcess = process;
            }
            catch (OperationCanceledException)
            {
                process.Kill(true);
                throw new TimeoutException($"Certutil streaming command timed out after 30 minutes. Arguments: {arguments}");
            }

            var reader = startedProcess.StandardOutput;
            string? line;
            var lineCount = 0;
            
            while ((line = await reader.ReadLineAsync()) != null)
            {
                yield return line;
                lineCount++;
                

                
                if (cts.Token.IsCancellationRequested)
                    break;
            }

            try
            {
                await startedProcess.WaitForExitAsync(cts.Token);

                if (errorOutput.Any())
                {
                    var firstError = errorOutput.First();
                    if (firstError.Contains("The system cannot find the file specified."))
                    {
                        throw new InvalidOperationException($"Certutil command failed because the local CA database was not found. This command must be run on a CA server. Error: {firstError}");
                    }
                    
                    foreach (var error in errorOutput)
                    {
                        Logger.LogError($"Certutil error: {error}");
                    }
                }
            }
            catch (OperationCanceledException)
            {
                startedProcess.Kill(true);
                throw new TimeoutException($"Certutil streaming command timed out after 30 minutes. Arguments: {arguments}");
            }
        }

        private async Task<List<string>> RunCertutilAsync(string arguments)
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "certutil.exe",
                    Arguments = arguments,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            var output = new List<string>();
            var errorOutput = new List<string>();
            using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(10));

            process.OutputDataReceived += (sender, args) => 
            { 
                if (args.Data != null) 
                {
                    output.Add(args.Data);
                    

                }
            };
            
            process.ErrorDataReceived += (sender, args) => { if (args.Data != null) errorOutput.Add(args.Data); };

            try
            {
                process.Start();
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();

                await process.WaitForExitAsync(cts.Token);

                if (errorOutput.Any())
                {
                    var firstError = errorOutput.First();
                    if (firstError.Contains("The system cannot find the file specified."))
                    {
                         throw new InvalidOperationException($"Certutil command failed because the local CA database was not found. This command must be run on a CA server. Error: {firstError}");
                    }
                    output.AddRange(errorOutput);
                }
            }
            catch (OperationCanceledException)
            {
                process.Kill(true);
                throw new TimeoutException($"Certutil command timed out after 10 minutes. Arguments: {arguments}");
            }

            Logger.LogInfo($"Collected {output.Count} lines from certutil command: {arguments}");
            return output;
        }

        private void ParseSubjectAlternativeNames(Certificate cert, string text)
        {
            var upn = "";

            if (TryExtractMatch(text, @"SAN:upn=([^""\r\n]+)", out var sanUpnExtraction))
            {
                upn = sanUpnExtraction;
            }
            else if (TryExtractMatch(text, @"upn=([^,\r\n\s]+)", out var sanUpnGeneric))
            {
                upn = sanUpnGeneric.Trim();
            }

            if (!string.IsNullOrEmpty(upn))
            {
                cert.ContainsSAN = true;
                cert.SANUPN = upn;
                cert.Principal = $"SAN:upn={upn}";
                cert.IsSuspicious = true;

                Logger.LogInfo($"CERT_DECISION: [Intense] Request {cert.RequestID} ({cert.TemplateName}) = SUSPICIOUS | Requester: {cert.Requester ?? "Unknown"} | SAN: {upn} | Status: {cert.DispositionMsg ?? "N/A"}");
            }
            else
            {
                cert.ContainsSAN = false;
                cert.SANUPN = "N/A";
                cert.IsSuspicious = false;
                
                Logger.LogCertificateDecision(cert.RequestID, cert.TemplateName, false, "No Subject Alternative Name found");
            }
        }

        private void ParseClientInformation(Certificate cert, string text)
        {
            if (TryExtractMatch(text, @"Machine:\s*=?\s*([^\r\n]+)", out var machine))
            {
                cert.Machine = machine.Trim();
            }
            else if (TryExtractMatch(text, @"Machine:\s*([^\r\n]+)", out var machineAlt))
            {
                cert.Machine = machineAlt.Trim();
            }

            if (TryExtractMatch(text, @"Process:\s*=?\s*([^\r\n]+)", out var process))
            {
                cert.Process = process.Trim();
            }
            else if (TryExtractMatch(text, @"Process:\s*([^\r\n]+)", out var processAlt))
            {
                cert.Process = processAlt.Trim();
            }

            if (string.IsNullOrEmpty(cert.Machine))
                cert.Machine = "N/A";
            if (string.IsNullOrEmpty(cert.Process))
                cert.Process = "N/A";
        }

        private bool IsDefaultTemplate(string templateName)
        {
            var defaultTemplates = new[] { "user", "machine", "computer", "webserver", "domaincontroller" };
            return defaultTemplates.Contains(templateName.ToLower());
        }

        private bool IsESC1Template(string templateName)
        {
            return _state.ESC1VulnTemplates.Any(t => 
                t.DisplayName.Equals(templateName, StringComparison.OrdinalIgnoreCase));
        }

        private bool IsCustomTemplateWithEnrolleeSuppliesSubject(string templateName)
        {
            return IsESC1Template(templateName);
        }

        private bool IsESC2Template(string templateName)
        {
            return _state.ESC2VulnTemplates.Any(t => 
                t.DisplayName.Equals(templateName, StringComparison.OrdinalIgnoreCase));
        }

        private bool IsESC3Template(string templateName)
        {
            return _state.ESC3VulnTemplates.Any(t => 
                t.DisplayName.Equals(templateName, StringComparison.OrdinalIgnoreCase));
        }

        private bool IsESC4Template(string templateName)
        {
            return _state.ESC4VulnTemplates.Any(t => 
                t.DisplayName.Equals(templateName, StringComparison.OrdinalIgnoreCase));
        }

        private bool IsPrivilegedRequester(string accountName)
        {
            if (string.IsNullOrEmpty(accountName))
                return false;

            var normalizedName = accountName.ToLower().Trim();

            if (Constants.ExcludedGroups.Any(pg => normalizedName.Contains(pg.ToLower())))
                return true;

            return false;
        }

        private List<string> GetUserGroupMemberships(string username)
        {
            var groups = new List<string>();
            Logger.LogInfo($"Getting group memberships for user '{username}' in intense mode");

            try
            {
                DirectorySearcher? searcher = null;
                
                try
                {
                    var domainName = System.Net.Dns.GetHostEntry(Environment.MachineName).HostName;
                    if (domainName.Contains("."))
                    {
                        domainName = domainName.Substring(domainName.IndexOf(".") + 1);
                        var domainEntry = new DirectoryEntry($"LDAP://{domainName}");
                        searcher = new DirectorySearcher(domainEntry);
                        Logger.LogInfo("Intense mode user group lookup LDAP connection method 1: SUCCESS");
                    }
                }
                catch (Exception)
                {
                    try
                    {
                        var domainEntry = new DirectoryEntry("LDAP://RootDSE");
                        var defaultNC = domainEntry.Properties["defaultNamingContext"][0]?.ToString();
                        var rootEntry = new DirectoryEntry($"LDAP://{defaultNC}");
                        searcher = new DirectorySearcher(rootEntry);
                        Logger.LogInfo("Intense mode user group lookup LDAP connection method 2: SUCCESS");
                    }
                    catch (Exception)
                    {
                        var domainEntry = new DirectoryEntry();
                        searcher = new DirectorySearcher(domainEntry);
                        Logger.LogInfo("Intense mode user group lookup LDAP connection method 3: SUCCESS");
                    }
                }

                if (searcher != null)
                {
                    using (searcher)
                    {
                        searcher.Filter = $"(&(objectClass=user)(sAMAccountName={username}))";
                        searcher.PropertiesToLoad.Add("memberOf");
                        searcher.PropertiesToLoad.Add("primaryGroupID");
                        searcher.PropertiesToLoad.Add("objectSid");
                        
                        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
                        var result = searcher.FindOne();
                        stopwatch.Stop();
                        
                        if (result?.Properties["memberOf"] != null)
                        {
                            foreach (string groupDN in result.Properties["memberOf"])
                            {
                                var cnIndex = groupDN.IndexOf("CN=", StringComparison.OrdinalIgnoreCase);
                                if (cnIndex >= 0)
                                {
                                    var cnValue = groupDN.Substring(cnIndex + 3);
                                    var commaIndex = cnValue.IndexOf(',');
                                    if (commaIndex > 0)
                                        cnValue = cnValue.Substring(0, commaIndex);
                                    groups.Add(cnValue);
                                }
                            }
                        }
                        
                        if (result != null)
                        {
                            var primaryGroupName = GetUserPrimaryGroup(result, searcher);
                            if (!string.IsNullOrEmpty(primaryGroupName) && !groups.Contains(primaryGroupName))
                            {
                                groups.Add(primaryGroupName);
                            }
                        }
                        
                        Logger.LogInfo($"Group memberships for user '{username}' retrieved in {stopwatch.ElapsedMilliseconds}ms in intense mode, found {groups.Count} groups");
                        Core.PerformanceMetrics.IncrementGroupMembershipQuery(false);
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.LogError($"Failed to get group memberships for user '{username}' in intense mode", ex);
            }

            return groups;
        }

        private string? GetUserPrimaryGroup(SearchResult? userResult, DirectorySearcher? searcher)
        {
            try
            {
                if (userResult?.Properties["primaryGroupID"] == null || userResult.Properties["objectSid"] == null)
                    return null;

                var primaryGroupID = Convert.ToInt32(userResult.Properties["primaryGroupID"][0]);
                var userSidBytes = (byte[])userResult.Properties["objectSid"][0];
                var userSid = new System.Security.Principal.SecurityIdentifier(userSidBytes, 0);
                
                var userSidString = userSid.Value;
                var lastHyphenIndex = userSidString.LastIndexOf('-');
                if (lastHyphenIndex < 0)
                    return null;

                var domainSid = userSidString.Substring(0, lastHyphenIndex);
                var primaryGroupSidString = $"{domainSid}-{primaryGroupID}";
                var primaryGroupSid = new System.Security.Principal.SecurityIdentifier(primaryGroupSidString);
                var primaryGroupSidBytes = new byte[primaryGroupSid.BinaryLength];
                primaryGroupSid.GetBinaryForm(primaryGroupSidBytes, 0);

                if (searcher != null)
                {
                    try
                    {
                        var sidEscaped = string.Join("", primaryGroupSidBytes.Select(b => $"\\{b:X2}"));
                        var sidFilter = $"(objectSid={sidEscaped})";
                        searcher.Filter = sidFilter;
                        searcher.PropertiesToLoad.Clear();
                        searcher.PropertiesToLoad.Add("sAMAccountName");
                        
                        var groupResult = searcher.FindOne();
                        if (groupResult?.Properties["sAMAccountName"] != null && groupResult.Properties["sAMAccountName"].Count > 0)
                        {
                            return groupResult.Properties["sAMAccountName"][0]?.ToString();
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.LogError($"Failed to resolve primary group SID '{primaryGroupSidString}' to group name", ex);
                    }
                }

                return null;
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error getting user primary group", ex);
                return null;
            }
        }

        /// <summary>
        /// Filter certificates based on start date (if configured)
        /// </summary>
        /// <param name="certificates">List of certificates to filter</param>
        /// <returns>Filtered list of certificates</returns>
        private List<Certificate> FilterCertificatesByDate(List<Certificate> certificates)
        {
            if (!_state.StartDate.HasValue)
            {
                return certificates;
            }

            var filteredCerts = new List<Certificate>();
            var startDate = _state.StartDate.Value;
            var filterCount = 0;

            foreach (var cert in certificates)
            {
                if (TryParseCertificateDate(cert.SubmissionDate, out DateTime certDate))
                {
                    if (certDate >= startDate)
                    {
                        filteredCerts.Add(cert);
                    }
                    else
                    {
                        filterCount++;
                        Logger.LogInfo($"Certificate filtered out by start date: RequestID {cert.RequestID}, SubmissionDate {cert.SubmissionDate}");
                    }
                }
                else
                {
                    filteredCerts.Add(cert);
                    if (!string.IsNullOrEmpty(cert.SubmissionDate))
                    {
                        Logger.LogWarning($"Could not parse submission date '{cert.SubmissionDate}' for RequestID {cert.RequestID} - including in results");
                    }
                }
            }

            if (filterCount > 0)
            {
                var startDateStr = DateHelper.FormatDateForDisplay(startDate);
                Logger.LogInfo($"Date filtering applied: {filterCount} certificates filtered out (before {startDateStr}), {filteredCerts.Count} certificates remain");
            }

            return filteredCerts;
        }

        /// <summary>
        /// Try to parse a certificate date string from certutil output
        /// </summary>
        /// <param name="dateString">Date string from certificate</param>
        /// <param name="parsedDate">Parsed date if successful</param>
        /// <returns>True if parsing was successful</returns>
        private bool TryParseCertificateDate(string dateString, out DateTime parsedDate)
        {
            parsedDate = DateTime.MinValue;

            if (string.IsNullOrWhiteSpace(dateString))
                return false;

            string[] formats = {
                "M/d/yyyy h:mm:ss tt",    // 12/25/2023 10:30:00 AM
                "M/d/yyyy h:mm tt",       // 12/25/2023 10:30 AM
                "MM/dd/yyyy HH:mm:ss",    // 12/25/2023 10:30:00
                "yyyy-MM-dd HH:mm:ss",    // 2023-12-25 10:30:00
                "MMM d, yyyy h:mm:ss tt", // Dec 25, 2023 10:30:00 AM
                "MMM d, yyyy h:mm tt",    // Dec 25, 2023 10:30 AM
                "M/d/yyyy",               // 12/25/2023
                "MM/dd/yyyy",             // 12/25/2023
                "yyyy-MM-dd",
            };

            foreach (var format in formats)
            {
                if (DateTime.TryParseExact(dateString.Trim(), format,
                    System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.None, out parsedDate))
                {
                    return true;
                }
            }

            if (DateTime.TryParse(dateString.Trim(), out parsedDate))
            {
                return true;
            }

            return false;
        }



    }
} 