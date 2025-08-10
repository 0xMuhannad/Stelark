using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.IO;
using System.Threading;

namespace Stelark
{
    public class CertificateAnalyzer
    {
        private readonly GlobalState _state;

        public CertificateAnalyzer(GlobalState state)
        {
            _state = state;
        }

        public async Task HuntESC1CertificatesAsync()
        {
            if (!_state.IsLocalCAServer || _state.ESC1VulnTemplates.Count == 0)
                return;

            ConsoleHelper.WriteInfo("Hunting for certificates issued by ESC1-Vulnerable templates...");
            Logger.LogInfo("Hunting for certificates issued by ESC1-Vulnerable templates...");
            
            _state.CertutilErrorDetected_ESC1 = false;
            var allCerts = await HuntCertificatesByTemplatesAsync(_state.ESC1VulnTemplates);
            
            _state.ESC1Certificates = allCerts;
            _state.ESC1Certificates.ForEach(c =>
            {
                c.Source = "ESC1";
                // Only mark as suspicious if certificate has SAN
                c.IsSuspicious = c.ContainsSAN;
                
                // Log certificate decision
                var reason = c.ContainsSAN ? $"Has SAN: {c.SANUPN}" : "No Subject Alternative Name";
                Logger.LogCertificateDecision(c.RequestID, c.TemplateName, c.IsSuspicious, reason);
                
                // Log certificate details for analysis
                Logger.LogCertificateAnalysis(c.RequestID, "Requester", c.Requester, "Certificate requester identity", "ESC1");
                Logger.LogCertificateAnalysis(c.RequestID, "Template", c.TemplateName, "Template used for certificate", "ESC1");
                Logger.LogCertificateAnalysis(c.RequestID, "Status", c.DispositionMsg, "Certificate issuance status", "ESC1");
                if (!string.IsNullOrEmpty(c.SANUPN) && c.SANUPN != "N/A")
                    Logger.LogCertificateAnalysis(c.RequestID, "SAN", c.SANUPN, "Subject Alternative Name present", "ESC1");
            });
            _state.SuspiciousESC1CertCount = _state.ESC1Certificates.Count(c => c.IsSuspicious);
            
            Logger.LogQuery("Certificate Hunt", "ESC1 Templates", _state.ESC1Certificates.Count);
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

        public async Task HuntESC2CertificatesAsync()
        {
            if (!_state.IsLocalCAServer || _state.ESC2VulnTemplates.Count == 0)
                return;

            ConsoleHelper.WriteInfo("Hunting for certificates issued by ESC2-Vulnerable templates...");
            
            _state.CertutilErrorDetected_ESC2 = false;
            var allCerts = await HuntCertificatesByTemplatesAsync(_state.ESC2VulnTemplates);
            
            _state.ESC2Certificates = allCerts;
            _state.ESC2Certificates.ForEach(c =>
            {
                c.Source = "ESC2";
                // Only mark as suspicious if certificate has SAN
                c.IsSuspicious = c.ContainsSAN;
                
                // Log certificate decision
                var reason = c.ContainsSAN ? $"Has SAN: {c.SANUPN}" : "No Subject Alternative Name";
                Logger.LogCertificateDecision(c.RequestID, c.TemplateName, c.IsSuspicious, reason);
                
                // Log certificate details for analysis
                Logger.LogCertificateAnalysis(c.RequestID, "Requester", c.Requester, "Certificate requester identity", "ESC2");
                Logger.LogCertificateAnalysis(c.RequestID, "Template", c.TemplateName, "Template used for certificate", "ESC2");
                Logger.LogCertificateAnalysis(c.RequestID, "Status", c.DispositionMsg, "Certificate issuance status", "ESC2");
                if (!string.IsNullOrEmpty(c.SANUPN) && c.SANUPN != "N/A")
                    Logger.LogCertificateAnalysis(c.RequestID, "SAN", c.SANUPN, "Subject Alternative Name present", "ESC2");
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

        public async Task HuntESC3CertificatesAsync()
        {
            if (!_state.IsLocalCAServer || _state.ESC3VulnTemplates.Count == 0)
                return;

            ConsoleHelper.WriteInfo("Hunting for certificates issued by ESC3-Vulnerable templates...");
            
            _state.CertutilErrorDetected_ESC3 = false;
            var allCerts = await HuntCertificatesByTemplatesAsync(_state.ESC3VulnTemplates);
            
            _state.ESC3Certificates = allCerts;
            _state.ESC3Certificates.ForEach(c =>
            {
                c.Source = "ESC3";
                // Only mark as suspicious if certificate has SAN
                c.IsSuspicious = c.ContainsSAN;
                
                // Log certificate decision
                var reason = c.ContainsSAN ? $"Has SAN: {c.SANUPN}" : "No Subject Alternative Name";
                Logger.LogCertificateDecision(c.RequestID, c.TemplateName, c.IsSuspicious, reason);
                
                // Log certificate details for analysis
                Logger.LogCertificateAnalysis(c.RequestID, "Requester", c.Requester, "Certificate requester identity", "ESC3");
                Logger.LogCertificateAnalysis(c.RequestID, "Template", c.TemplateName, "Template used for certificate", "ESC3");
                Logger.LogCertificateAnalysis(c.RequestID, "Status", c.DispositionMsg, "Certificate issuance status", "ESC3");
                if (!string.IsNullOrEmpty(c.SANUPN) && c.SANUPN != "N/A")
                    Logger.LogCertificateAnalysis(c.RequestID, "SAN", c.SANUPN, "Subject Alternative Name present", "ESC3");
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

        public async Task HuntESC4CertificatesAsync()
        {
            if (!_state.IsLocalCAServer || _state.ESC4VulnTemplates.Count == 0)
                return;

            ConsoleHelper.WriteInfo("Hunting for certificates issued by ESC4-Vulnerable templates...");
            
            _state.CertutilErrorDetected_ESC4 = false;
            var allCerts = await HuntCertificatesByTemplatesAsync(_state.ESC4VulnTemplates);
            
            _state.ESC4Certificates = allCerts;
            _state.ESC4Certificates.ForEach(c =>
            {
                c.Source = "ESC4";
                // Only mark as suspicious if certificate has SAN
                c.IsSuspicious = c.ContainsSAN;
                
                // Log certificate decision
                var reason = c.ContainsSAN ? $"Has SAN: {c.SANUPN}" : "No Subject Alternative Name";
                Logger.LogCertificateDecision(c.RequestID, c.TemplateName, c.IsSuspicious, reason);
                
                // Log certificate details for analysis
                Logger.LogCertificateAnalysis(c.RequestID, "Requester", c.Requester, "Certificate requester identity", "ESC4");
                Logger.LogCertificateAnalysis(c.RequestID, "Template", c.TemplateName, "Template used for certificate", "ESC4");
                Logger.LogCertificateAnalysis(c.RequestID, "Status", c.DispositionMsg, "Certificate issuance status", "ESC4");
                if (!string.IsNullOrEmpty(c.SANUPN) && c.SANUPN != "N/A")
                    Logger.LogCertificateAnalysis(c.RequestID, "SAN", c.SANUPN, "Subject Alternative Name present", "ESC4");
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

        public async Task HuntIntenseCertificatesAsync()
        {
            if (!_state.IsLocalCAServer && !_state.AllowIntenseFallback)
                return;

            ConsoleHelper.WriteInfo("Running intense mode: full certificate enumeration (this may take a while)...");

            
            _state.CertutilErrorDetected_Intense = false;
            
            try
            {
                MemoryManager.LogMemoryUsage("before intense enumeration");
                
                // Use streaming approach instead of loading all certificates at once
                var intenseCerts = new List<Certificate>();
                var totalProcessed = await ProcessCertificatesInBatchesAsync(intenseCerts);
                
                _state.IntenseCertificates = intenseCerts;
                _state.IntenseModeProcessedCount = totalProcessed; // Store for summary calculations
                
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
                Logger.LogError("Failed to run intense certificate enumeration", ex);
                ConsoleHelper.WriteError($"Failed to run intense certificate enumeration: {ex.Message}");
                _state.CertutilErrorDetected_Intense = true;
            }
        }

        private async Task<int> ProcessCertificatesInBatchesAsync(List<Certificate> intenseCerts)
        {
            // Initialize fast lookup tables for performance
            InitializeFastLookups();
            
            var currentBlock = new List<string>();
            var totalCertificatesProcessed = 0;
            var batchCount = 0;
            
            // Performance tracking
            var skippedNoSAN = 0;
            var skippedAlreadyAnalyzed = 0; // Templates already analyzed by normal ESC scans
            var skippedAlreadyReported = 0;
            var fullParsed = 0;
            
            await foreach (var line in StreamCertutilViewAsync())
            {
                if (line.StartsWith("Row ") && Regex.IsMatch(line, @"^Row [0-9]+:"))
                {
                    if (currentBlock.Count > 0)
                    {
                        totalCertificatesProcessed++;
                        
                        // FAST DETECTION: Step 1 - Check for SAN first (immediate skip if no SAN)
                        if (!HasSANInBlock(currentBlock))
                        {
                            // Skip - no SAN means not suspicious
                            skippedNoSAN++;
                            currentBlock.Clear();
                            continue;
                        }
                        
                        // FAST DETECTION: Step 2 - Extract template name and check if already analyzed
                        var templateName = ExtractTemplateNameFromBlock(currentBlock);
                        if (IsTemplateVulnerable(templateName))
                        {
                            // Skip - template already analyzed by normal ESC scans
                            skippedAlreadyAnalyzed++;
                            currentBlock.Clear();
                            continue;
                        }
                        
                        // FAST DETECTION: Step 3 - Check if already reported by ESC1-4
                        var requestId = ExtractRequestIDFromBlock(currentBlock);
                        if (IsAlreadyReported(requestId))
                        {
                            // Skip - already found in normal ESC analysis
                            skippedAlreadyReported++;
                            currentBlock.Clear();
                            continue;
                        }
                        
                        // Only do full parsing for certificates that pass all fast checks
                        fullParsed++;
                        var certObj = ParseCertutilCertBlock(currentBlock);
                        if (certObj != null && !string.IsNullOrEmpty(certObj.RequestID) && certObj.IsSuspicious)
                        {
                            certObj.RequestID = certObj.RequestID.NormalizeRequestID();
                            certObj.RawCertutilBlock = string.Join("\n", currentBlock);
                            certObj.Source = "Intense";
                            intenseCerts.Add(certObj);
                        }
                        
                        // Check memory and batch limits
                        if (totalCertificatesProcessed % _state.BatchSize == 0)
                        {
                            batchCount++;
                            Logger.LogInfo($"Processed batch {batchCount} ({totalCertificatesProcessed} certificates total, {intenseCerts.Count} suspicious)");
                            ConsoleHelper.WriteInfo($"Batch {batchCount} complete: {totalCertificatesProcessed:N0} certificates processed, {intenseCerts.Count:N0} suspicious found");
                            

                            

                        }
                    }
                    currentBlock.Clear();
                }
                currentBlock.Add(line);
            }

            // Process the last block
            if (currentBlock.Count > 0)
            {
                totalCertificatesProcessed++;
                
                // Apply fast detection to last block too
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
                                certObj.RequestID = certObj.RequestID.NormalizeRequestID();
                                certObj.RawCertutilBlock = string.Join("\n", currentBlock);
                                certObj.Source = "Intense";
                                intenseCerts.Add(certObj);
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

            // Log performance improvements
            var totalSkipped = skippedNoSAN + skippedAlreadyAnalyzed + skippedAlreadyReported;
            var skipPercentage = totalCertificatesProcessed > 0 ? (totalSkipped * 100.0 / totalCertificatesProcessed) : 0;
            
            Logger.LogInfo($"Fast Detection Performance: {skipPercentage:F1}% certificates skipped without full parsing");
            Logger.LogInfo($"  - No SAN: {skippedNoSAN:N0} certificates");
            Logger.LogInfo($"  - Already analyzed templates: {skippedAlreadyAnalyzed:N0} certificates");
            Logger.LogInfo($"  - Already reported: {skippedAlreadyReported:N0} certificates");
            Logger.LogInfo($"  - Full parsing for historical analysis: {fullParsed:N0} certificates");
            
            ConsoleHelper.WriteInfo($"Fast detection optimization: {skipPercentage:F1}% parsing avoided ({totalSkipped:N0} of {totalCertificatesProcessed:N0})");
            
            return totalCertificatesProcessed;
        }

        public void DeduplicateIntenseCertificates()
        {
            if (_state.IntenseCertificates.Count == 0)
                return;

            // Build a set of RequestIDs from ESC1, ESC2, ESC3, and ESC4 findings
            var reportedIDs = new HashSet<string>();

            // Add suspicious ESC1 certificates
            foreach (var cert in _state.ESC1Certificates)
            {
                reportedIDs.Add(cert.RequestID.NormalizeRequestID());
            }

            // Add all ESC2 certificates
            foreach (var cert in _state.ESC2Certificates)
            {
                reportedIDs.Add(cert.RequestID.NormalizeRequestID());
            }

            // Add all ESC3 certificates
            foreach (var cert in _state.ESC3Certificates)
            {
                reportedIDs.Add(cert.RequestID.NormalizeRequestID());
            }

            // Add all ESC4 certificates
            foreach (var cert in _state.ESC4Certificates)
            {
                reportedIDs.Add(cert.RequestID.NormalizeRequestID());
            }

            // Filter intense mode certificates to find unique ones
            _state.IntenseUniqueCertificates = _state.IntenseCertificates
                .Where(cert => !reportedIDs.Contains(cert.RequestID.NormalizeRequestID()))
                .ToList();
        }

        private async Task<List<Certificate>> HuntCertificatesByTemplatesAsync(List<VulnerableTemplate> templates)
        {
            var allFoundCerts = new List<Certificate>();
            var templateLookup = BuildTemplateLookup(templates);
            var vulnerabilityType = templates.FirstOrDefault()?.VulnerabilityType;

            MemoryManager.LogMemoryUsage($"before hunting {vulnerabilityType} certificates");

            foreach (var template in templates)
            {
                try
                {


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
                    Logger.LogError($"Failed to hunt certificates for template {template.DisplayName}", ex);
                    ConsoleHelper.WriteError($"Failed to hunt certificates for template {template.DisplayName}: {ex.Message}");
                }
            }

            var deduplicatedCerts = allFoundCerts.GroupBy(c => new { c.Serial, c.RequestID })
                                                 .Select(g => g.First())
                                                 .ToList();

            MemoryManager.LogMemoryUsage($"after hunting {vulnerabilityType} certificates");
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

            // Detect certutil errors
            if (certutilOutputs.Any(line => line.StartsWith("CertUtil:")))
            {
                // Set appropriate error flag based on context
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
            
            // Performance tracking
            var totalProcessed = 0;
            var skippedNoSAN = 0;
            var fullParsed = 0;

            foreach (var line in certutilOutputs)
            {
                if (line.StartsWith("Row ") && Regex.IsMatch(line, @"^Row [0-9]+:"))
                {
                    if (currentBlock.Count > 0)
                    {
                        totalProcessed++;
                        
                        // FAST DETECTION: Check for SAN first (immediate skip if no SAN)
                        if (!HasSANInBlock(currentBlock))
                        {
                            // Skip - no SAN means not suspicious for ADCS attacks
                            skippedNoSAN++;
                            currentBlock.Clear();
                            continue;
                        }
                        
                        // Only do full parsing for certificates that have SAN
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
                
                // Apply fast detection to last block too
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
            
            // Log performance improvements for this template
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
                     Regex.IsMatch(certObj.TemplateName, @"^[0-9]+(\.[0-9]+)+$") && 
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
                // Log unmapped template
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

            // Parse basic fields
            if (TryExtractMatch(text, @"Request ID: ""?([^""\r\n]+)""?", out var requestId))
                cert.RequestID = requestId;

            if (TryExtractMatch(text, @"Requester Name: ""?([^""\r\n]+)""?", out var requester))
                cert.Requester = requester;

            // Parse template name with tiered approach
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

            // Check for friendly name in extensions
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

            // Fallback: Try to extract from Request Attributes
            if (string.IsNullOrEmpty(cert.TemplateName) || 
                Regex.IsMatch(cert.TemplateName, @"^[0-9]+(\.[0-9]+)+$"))
            {
                if (TryExtractMatch(text, @"Request Attributes:.*CertificateTemplate:([^\s\r\n""]+)", out var attrTemplate))
                {
                    cert.TemplateName = attrTemplate;
                }
                else if (TryExtractMatch(text, @"(?m)^\s+CertificateTemplate: ""([^""]+)""", out var quotedTemplate))
                {
                    if (!Regex.IsMatch(quotedTemplate, @"^[0-9]+(\.[0-9]+)+$"))
                    {
                        cert.TemplateName = quotedTemplate.Trim();
                    }
                }
            }

            cert.Template = cert.TemplateName;

            // Parse other fields
            if (TryExtractMatch(text, @"Request Disposition Message: ""?([^""\r\n]+)""?", out var disposition))
                cert.DispositionMsg = disposition;

            if (TryExtractMatch(text, @"Request Submission Date: ([^\r\n]+)", out var submission))
                cert.SubmissionDate = submission.Trim();

            if (TryExtractMatch(text, @"Certificate Effective Date: ([^\r\n]+)", out var effective))
                cert.NotBefore = effective.Trim();

            if (TryExtractMatch(text, @"Certificate Expiration Date: ([^\r\n]+)", out var expiration))
                cert.NotAfter = expiration.Trim();
            
            // Find the correct serial number by checking all occurrences.
            var serialLines = lines.Where(l => l.Trim().StartsWith("Serial Number:"));
            foreach (var line in serialLines)
            {
                var match = Regex.Match(line, @"Serial Number: ""?([^""\r\n]+)""?");
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

            // Enhanced SAN UPN parsing with ESC1/ESC6 detection
            ParseSubjectAlternativeNames(cert, text);

            // Parse Client Information (Machine and Process)
            ParseClientInformation(cert, text);

            // Parse EKUs
            cert.EKUs = ParseEKUs(text);

            // Set N/A for missing fields
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
                if (Regex.IsMatch(line, @"^\s*Enhanced Key Usage\s*$") || 
                    Regex.IsMatch(line, @"^\s*Application Policies\s*$"))
                {
                    int j = i + 1;
                    while (j < lines.Length && Regex.IsMatch(lines[j], @"^\s+"))
                    {
                        var ekuLine = lines[j].Trim();
                        var match = Regex.Match(ekuLine, @"([A-Za-z0-9 .\-]+)?\s*\(?([0-9.]+)\)?");
                        if (match.Success)
                        {
                            var ekuName = match.Groups[1].Success ? match.Groups[1].Value.Trim() : "";
                            var ekuOID = match.Groups[2].Success ? match.Groups[2].Value.Trim() : "";
                            
                            if (!string.IsNullOrEmpty(ekuOID))
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

        private bool IsSuspiciousCert(Certificate cert)
        {
            // Use the enhanced suspicious detection from ParseSubjectAlternativeNames
            if (cert.IsSuspicious)
                return true;
                
            // Any certificate with SAN is considered suspicious
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

        // Fast detection methods for performance optimization
        private bool HasSANInBlock(List<string> block)
        {
            // Quick SAN detection without full parsing
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
            // Fast template name extraction without full parsing
            foreach (var line in block)
            {
                if (line.Contains("Certificate Template:"))
                {
                    // Try to extract template name quickly
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
            // Fast RequestID extraction without full parsing
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
            // Build fast lookup sets for template names
            _vulnerableTemplateNames = new HashSet<string>();
            foreach (var template in _state.ESC1VulnTemplates.Concat(_state.ESC2VulnTemplates)
                                           .Concat(_state.ESC3VulnTemplates).Concat(_state.ESC4VulnTemplates))
            {
                _vulnerableTemplateNames.Add(template.DisplayName);
                _vulnerableTemplateNames.Add(template.CN);
                if (!string.IsNullOrEmpty(template.OID))
                    _vulnerableTemplateNames.Add(template.OID);
            }

            // Build fast lookup set for already reported certificate IDs
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

            // Stream lines outside of try-catch to avoid yield return restriction
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
                    
                    // Log errors but don't stop streaming
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
            using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(10)); // Extended timeout

            // Memory-aware data receiving
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

            // Extract SAN UPN first
            if (TryExtractMatch(text, @"SAN:upn=([^""\r\n]+)", out var sanUpnExtraction))
            {
                upn = sanUpnExtraction;
            }
            else if (TryExtractMatch(text, @"upn=([^,\r\n\s]+)", out var sanUpnGeneric))
            {
                upn = sanUpnGeneric.Trim();
            }

            // Process SAN information
            if (!string.IsNullOrEmpty(upn))
            {
                cert.ContainsSAN = true;
                cert.SANUPN = upn;
                cert.Principal = $"SAN:upn={upn}";

                // Enhanced privilege checking for intense mode
                var requesterName = cert.Requester?.Split('\\').LastOrDefault() ?? "";
                var isPrivilegedByName = IsPrivilegedRequester(requesterName);
                
                // For user accounts, also check their group memberships
                var isPrivilegedByGroupMembership = false;
                if (!isPrivilegedByName && !string.IsNullOrEmpty(requesterName) && !requesterName.EndsWith("$"))
                {
                    try
                    {
                        var userGroups = GetUserGroupMemberships(requesterName);
                        foreach (var group in userGroups)
                        {
                            if (IsPrivilegedRequester(group))
                            {
                                isPrivilegedByGroupMembership = true;
                                Logger.LogCertificateAnalysis(cert.RequestID, "PrivilegedByGroup", "TRUE", $"Requester '{requesterName}' belongs to privileged group: {group}", "Intense");
                                break;
                            }
                        }
                        if (!isPrivilegedByGroupMembership && userGroups.Count > 0)
                        {
                            Logger.LogCertificateAnalysis(cert.RequestID, "RequesterGroups", string.Join(", ", userGroups), $"Requester '{requesterName}' group memberships checked - none privileged", "Intense");
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.LogError($"Failed to get group memberships for requester '{requesterName}' in intense mode", ex);
                    }
                }

                // Determine if certificate is suspicious based on privilege status
                var isPrivileged = isPrivilegedByName || isPrivilegedByGroupMembership;
                cert.IsSuspicious = !isPrivileged; // Only suspicious if requester is NOT privileged
                
                // Log detailed analysis
                Logger.LogCertificateAnalysis(cert.RequestID, "Requester", cert.Requester ?? "Unknown", "Certificate requester identity", "Intense");
                Logger.LogCertificateAnalysis(cert.RequestID, "PrivilegedByName", isPrivilegedByName.ToString(), $"Requester '{requesterName}' is privileged by name: {isPrivilegedByName}", "Intense");
                Logger.LogCertificateAnalysis(cert.RequestID, "SAN_UPN", upn, "Subject Alternative Name with UPN present", "Intense");
                
                var suspiciousReason = cert.IsSuspicious ? $"Non-privileged requester '{cert.Requester}' has SAN UPN: {upn}" : $"Privileged requester '{cert.Requester}' has expected SAN UPN: {upn}";
                Logger.LogCertificateDecision(cert.RequestID, cert.TemplateName, cert.IsSuspicious, suspiciousReason);
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
            // Look for Client Information attribute section
            // Pattern matches various formats like:
            // Machine: SRV-APP.XYZ.TLP
            // Process: CertEnrollCtrl.exe
            
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

            // Set N/A for empty fields
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
            // Check if this template is in our ESC1 vulnerable templates list
            return _state.ESC1VulnTemplates.Any(t => 
                t.DisplayName.Equals(templateName, StringComparison.OrdinalIgnoreCase));
        }

        private bool IsCustomTemplateWithEnrolleeSuppliesSubject(string templateName)
        {
            // Legacy method - use IsESC1Template instead
            return IsESC1Template(templateName);
        }

        private bool IsESC2Template(string templateName)
        {
            // Check if this template is in our ESC2 vulnerable templates list
            return _state.ESC2VulnTemplates.Any(t => 
                t.DisplayName.Equals(templateName, StringComparison.OrdinalIgnoreCase));
        }

        private bool IsESC3Template(string templateName)
        {
            // Check if this template is in our ESC3 vulnerable templates list
            return _state.ESC3VulnTemplates.Any(t => 
                t.DisplayName.Equals(templateName, StringComparison.OrdinalIgnoreCase));
        }

        private bool IsESC4Template(string templateName)
        {
            // Check if this template is in our ESC4 vulnerable templates list
            return _state.ESC4VulnTemplates.Any(t => 
                t.DisplayName.Equals(templateName, StringComparison.OrdinalIgnoreCase));
        }

        private bool IsPrivilegedRequester(string accountName)
        {
            if (string.IsNullOrEmpty(accountName))
                return false;

            var normalizedName = accountName.ToLower().Trim();

            // Check against known privileged groups
            if (Constants.PrivilegedGroups.Any(pg => normalizedName.Contains(pg.ToLower())))
                return true;

            // Enhanced keyword-based detection (same as TemplateAnalyzer)
            var privilegedKeywords = new[] { 
                "admin", "administrator", "operator", "backup", "schema", "enterprise", 
                "certificate", "cert", "security", "exchange", "dns", "manager", 
                "supervisor", "privilege", "power", "service", "system", "infrastructure",
                "it", "tech", "root", "super", "elevated", "senior"
            };

            foreach (var keyword in privilegedKeywords)
            {
                if (normalizedName.Contains(keyword))
                    return true;
            }

            // Additional check: any account with "admin" in any form should be privileged
            if (normalizedName.Contains("admin"))
                return true;

            return false;
        }

        private List<string> GetUserGroupMemberships(string username)
        {
            var groups = new List<string>();
            Logger.LogInfo($"Getting group memberships for user '{username}' in intense mode");

            try
            {
                // Use optimized LDAP connection order
                DirectorySearcher? searcher = null;
                
                try
                {
                    // Method 1: DNS domain lookup (most reliable)
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
                        // Method 2: Default domain
                        var domainEntry = new DirectoryEntry("LDAP://RootDSE");
                        var defaultNC = domainEntry.Properties["defaultNamingContext"][0]?.ToString();
                        var rootEntry = new DirectoryEntry($"LDAP://{defaultNC}");
                        searcher = new DirectorySearcher(rootEntry);
                        Logger.LogInfo("Intense mode user group lookup LDAP connection method 2: SUCCESS");
                    }
                    catch (Exception)
                    {
                        // Method 3: Simple LDAP connection
                        var domainEntry = new DirectoryEntry();
                        searcher = new DirectorySearcher(domainEntry);
                        Logger.LogInfo("Intense mode user group lookup LDAP connection method 3: SUCCESS");
                    }
                }

                if (searcher != null)
                {
                    searcher.Filter = $"(&(objectClass=user)(sAMAccountName={username}))";
                    searcher.PropertiesToLoad.Add("memberOf");
                    
                    var stopwatch = System.Diagnostics.Stopwatch.StartNew();
                    var result = searcher.FindOne();
                    stopwatch.Stop();
                    
                    if (result?.Properties["memberOf"] != null)
                    {
                        foreach (string groupDN in result.Properties["memberOf"])
                        {
                            // Extract group name from DN (e.g., "CN=Admin,CN=Users,DC=domain,DC=com" -> "Admin")
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
                    
                    Logger.LogInfo($"Group memberships for user '{username}' retrieved in {stopwatch.ElapsedMilliseconds}ms in intense mode, found {groups.Count} groups");
                }
            }
            catch (Exception ex)
            {
                Logger.LogError($"Failed to get group memberships for user '{username}' in intense mode", ex);
            }

            return groups;
        }
    }
} 