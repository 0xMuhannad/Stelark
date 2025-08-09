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
            Logger.LogStatistic("Suspicious ESC1 Certificates", _state.SuspiciousESC1CertCount, "certificates with Subject Alternative Names");
            
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
        }

        public async Task HuntIntenseCertificatesAsync()
        {
            if (!_state.IsLocalCAServer && !_state.AllowIntenseFallback)
                return;

            ConsoleHelper.WriteInfo("Running intense mode: full certificate enumeration (this may take a while)...");
            
            _state.CertutilErrorDetected_Intense = false;
            
            try
            {
                var allCerts = await RunCertutilViewAsync();
                var intenseCerts = new List<Certificate>();
                var currentBlock = new List<string>();

                foreach (var line in allCerts)
                {
                    if (line.StartsWith("Row ") && Regex.IsMatch(line, @"^Row [0-9]+:"))
                    {
                        if (currentBlock.Count > 0)
                        {
                            var certObj = ParseCertutilCertBlock(currentBlock);
                            if (certObj != null && !string.IsNullOrEmpty(certObj.RequestID) && certObj.IsSuspicious)
                            {
                                certObj.RequestID = certObj.RequestID.NormalizeRequestID();
                                certObj.RawCertutilBlock = string.Join("\n", currentBlock);
                                certObj.Source = "Intense";
                                intenseCerts.Add(certObj);
                            }
                        }
                        currentBlock.Clear();
                    }
                    currentBlock.Add(line);
                }

                // Process the last block
                if (currentBlock.Count > 0)
                {
                    var certObj = ParseCertutilCertBlock(currentBlock);
                    if (certObj != null && !string.IsNullOrEmpty(certObj.RequestID) && certObj.IsSuspicious)
                    {
                        certObj.RequestID = certObj.RequestID.NormalizeRequestID();
                        certObj.RawCertutilBlock = string.Join("\n", currentBlock);
                        certObj.Source = "Intense";
                        intenseCerts.Add(certObj);
                    }
                }

                _state.IntenseCertificates = intenseCerts;
            }
            catch (Exception ex)
            {
                Logger.LogError("Failed to run intense certificate enumeration", ex);
                ConsoleHelper.WriteError($"Failed to run intense certificate enumeration: {ex.Message}");
                _state.CertutilErrorDetected_Intense = true;
            }
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

            return allFoundCerts.GroupBy(c => new { c.Serial, c.RequestID })
                                .Select(g => g.First())
                                .ToList();
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

            foreach (var line in certutilOutputs)
            {
                if (line.StartsWith("Row ") && Regex.IsMatch(line, @"^Row [0-9]+:"))
                {
                    if (currentBlock.Count > 0)
                    {
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
                var certObj = ParseCertutilCertBlock(currentBlock);
                if (certObj != null)
                {
                    certObj.RawCertutilBlock = string.Join("\n", currentBlock);
                    ProcessCertificateTemplate(certObj, templateLookup);
                    parsedCerts.Add(certObj);
                }
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

        private async Task<List<string>> RunCertutilViewAsync()
        {
            return await RunCertutilAsync("-v -view");
        }

        private async Task<List<string>> RunCertutilRestrictAsync(string restriction)
        {
            return await RunCertutilAsync($"-view -restrict \"{restriction}\"");
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
            using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(25));

            process.OutputDataReceived += (sender, args) => { if (args.Data != null) output.Add(args.Data); };
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
                throw new TimeoutException($"Certutil command timed out after 5 minutes. Arguments: {arguments}");
            }

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