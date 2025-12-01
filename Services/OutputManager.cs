using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using Stelark.Models;
using Stelark.Core;
using Stelark.Helpers;
using Stelark.Services;

namespace Stelark
{
    public class OutputManager
    {
        private readonly GlobalState _state;

        public OutputManager(GlobalState state)
        {
            _state = state;
        }

        public void PrintFindings(bool intenseOnly = false)
        {
            if (intenseOnly)
            {
                PrintIntenseFindings();
            }
            else
            {
                PrintFullFindings();
            }
        }

        public void PrintSummary(bool intenseOnly = false)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("==================== STELARK FINDINGS ====================");
            Console.ResetColor();

            if (intenseOnly)
            {
                PrintIntenseSummary();
            }
            else
            {
                PrintFullSummary();
            }

            Console.WriteLine("==========================================================");
        }

        public async Task SaveFindingsAsync(bool intenseOnly)
        {
            var outputDir = _state.OutputDir;
            Directory.CreateDirectory(outputDir);
            
            Logger.LogInfo($"Saving findings to: {outputDir}");
            Logger.LogInfo($"Intense Mode Only: {intenseOnly}");

            SaveIndividualCertificateFiles(outputDir, intenseOnly);
            await SaveIndividualTemplateFilesAsync(outputDir, intenseOnly);

            await SaveJsonReport(outputDir, intenseOnly);
            Logger.LogFileOperation("Generated", "JSON Report", "Success");
            
            await SaveHtmlReport(outputDir, intenseOnly);
            Logger.LogFileOperation("Generated", "HTML Report", "Success");
        }

        private void SaveIndividualCertificateFiles(string outputDir, bool intenseOnly)
        {
            if (!intenseOnly)
            {
                SaveCertificateGroupToFile(_state.ESC1Certificates, outputDir);
                SaveCertificateGroupToFile(_state.ESC2Certificates, outputDir);
                SaveCertificateGroupToFile(_state.ESC3Certificates, outputDir);
                SaveCertificateGroupToFile(_state.ESC4Certificates, outputDir);
            }
            SaveCertificateGroupToFile(_state.IntenseUniqueCertificates, outputDir);
        }
        
        private void SaveCertificateGroupToFile(List<Certificate> certificates, string outputDir)
        {
            foreach (var cert in certificates.Where(c => c.IsSuspicious))
            {
                try
                {
                    var decimalId = cert.RequestID.NormalizeRequestID();
                    var san = cert.ContainsSAN ? cert.SANUPN.Split('@')[0] : "NoSAN";
                    var tplName = !string.IsNullOrEmpty(cert.Template) ? cert.Template : cert.TemplateName;
                    
                    var sanitizedTpl = tplName.SanitizeFileName();
                    var sanitizedSan = san.SanitizeFileName();

                    var fileBase = $"{decimalId}-{sanitizedSan}-{sanitizedTpl}";
                    var fileName = $"{fileBase}.txt";
                    
                    var certsDir = Path.Combine(outputDir, "Certificates");
                    Directory.CreateDirectory(certsDir);

                    var tplDir = Path.Combine(certsDir, sanitizedTpl);
                    Directory.CreateDirectory(tplDir);

                    var filePath = Path.Combine(tplDir, fileName);
                    File.WriteAllText(filePath, cert.RawCertutilBlock);
                }
                catch (Exception ex)
                {
                    Logger.LogError($"Failed to save certificate file for Request ID {cert.RequestID}", ex);
                    ConsoleHelper.WriteError($"Failed to save certificate file for Request ID {cert.RequestID}: {ex.Message}");
                }
            }
        }

        private async Task SaveIndividualTemplateFilesAsync(string outputDir, bool intenseOnly)
        {
            if (intenseOnly) return;
            

            var hasVulnerableTemplates = _state.ESC1VulnTemplates.Count > 0 || 
                                       _state.ESC2VulnTemplates.Count > 0 || 
                                       _state.ESC3VulnTemplates.Count > 0 ||
                                       _state.ESC4VulnTemplates.Count > 0;
            
            if (!hasVulnerableTemplates) return;
            
            var templatesDir = Path.Combine(outputDir, "Templates");
            Directory.CreateDirectory(templatesDir);

            await SaveTemplateGroupToFileAsync(_state.ESC1VulnTemplates, templatesDir);
            await SaveTemplateGroupToFileAsync(_state.ESC2VulnTemplates, templatesDir);
            await SaveTemplateGroupToFileAsync(_state.ESC3VulnTemplates, templatesDir);
            await SaveTemplateGroupToFileAsync(_state.ESC4VulnTemplates, templatesDir);
        }
        
        private async Task SaveTemplateGroupToFileAsync(List<VulnerableTemplate> templates, string templatesDir)
        {
            foreach (var template in templates)
            {
                try
                {
                    var fileName = $"{template.CN.SanitizeFileName()}.txt";
                    var filePath = Path.Combine(templatesDir, fileName);

                    var certutilOutput = await RunProcessAndGetOutputAsync("certutil.exe", $"-v -template \"{template.CN}\"");
                    
                    await File.WriteAllTextAsync(filePath, certutilOutput);
                }
                catch (Exception ex)
                {
                    Logger.LogError($"Failed to save template file for {template.CN}", ex);
                    ConsoleHelper.WriteError($"Failed to save template file for {template.CN}: {ex.Message}");
                }
            }
        }

        
        private async Task SaveJsonReport(string outputDir, bool intenseOnly)
        {
            var jsonPath = Path.Combine(outputDir, "Stelark Findings.json");
            try
            {
                var findings = BuildJsonFindings(intenseOnly);
                var options = new JsonSerializerOptions { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
                var json = JsonSerializer.Serialize(findings, options);
                await File.WriteAllTextAsync(jsonPath, json);
            }
            catch (Exception ex)
            {
                Logger.LogError($"Failed to save JSON file: {jsonPath}", ex);
                ConsoleHelper.WriteError($"Failed to save JSON file: {jsonPath}. {ex.Message}");
            }
        }

        private async Task SaveHtmlReport(string outputDir, bool intenseOnly)
        {
            var htmlPath = Path.Combine(outputDir, "Stelark Report.html");
            try
            {
                var html = GenerateHtmlReport(intenseOnly);
                await File.WriteAllTextAsync(htmlPath, html);
            }
            catch (Exception ex)
            {
                Logger.LogError($"Failed to save HTML report: {htmlPath}", ex);
                ConsoleHelper.WriteError($"Failed to save HTML report: {htmlPath}. {ex.Message}");
            }
        }

        private object BuildJsonFindings(bool intenseOnly)
        {
            var result = new Dictionary<string, object>
            {
                ["Stelark"] = new Dictionary<string, object>()
            };
            
            var stelarkFindings = (Dictionary<string, object>)result["Stelark"];

            if (!_state.FoundCAServers)
            {
                stelarkFindings["Analysis_Status"] = "No CA Infrastructure Detected";
                stelarkFindings["CA_Discovery_Result"] = "No Certificate Authority servers found in Active Directory";
                stelarkFindings["Connectivity_Status"] = "AD connectivity may be limited or no AD CS infrastructure deployed";
                stelarkFindings["Checks_Performed"] = new[] { "CA Discovery" };
                stelarkFindings["Vulnerability_Analysis"] = "Not performed - no Certificate Authority infrastructure detected";
                stelarkFindings["Certificate_Analysis"] = "Not performed - no Certificate Authority infrastructure detected";
                stelarkFindings["Recommendation"] = "Ensure Active Directory connectivity and verify AD CS infrastructure is deployed";
                
                return result;
            }

            if (_state.FoundCAServers && !_state.IsLocalCAServer)
            {
                var caList = _state.CAServerHostnames.Count > 0 ? 
                    string.Join(", ", _state.CAServerHostnames) : "the CA server";
                
                stelarkFindings["Analysis_Status"] = "Limited Analysis - Not run on CA server";
                stelarkFindings["CA_Servers_Discovered"] = _state.CAServerHostnames.ToArray();
                stelarkFindings["Recommendation"] = $"Run Stelark directly on the CA server ({caList}) for complete AD CSsecurity assessment";
                stelarkFindings["Checks_Performed"] = new[] { "CA Discovery" };
                stelarkFindings["Vulnerability_Analysis"] = "Not performed - requires execution on Certificate Authority server";
                stelarkFindings["Certificate_Analysis"] = "Not performed - requires execution on Certificate Authority server";
                
                return result;
            }

            if (intenseOnly)
            {
                stelarkFindings["Intense_Suspicious_Certificates"] = _state.IntenseUniqueCertificates.Any()
                    ? _state.IntenseUniqueCertificates.Select(BuildCertificateJson).ToArray()
                    : "No Suspicious Certificates Were Identified via Intense Mode.";
            }
            else
            {
    
                stelarkFindings["Vulnerable_ESC1_Templates"] = _state.ESC1VulnTemplates.Any()
                    ? _state.ESC1VulnTemplates.Select(BuildTemplateJson).ToArray()
                    : "No Certificate Templates Vulnerable to ESC1 Were Found.";

                stelarkFindings["Vulnerable_ESC2_Templates"] = _state.ESC2VulnTemplates.Any()
                    ? _state.ESC2VulnTemplates.Select(BuildEsc2TemplateJson).ToArray()
                    : "No Vulnerable ESC2 Templates Found.";

                stelarkFindings["Vulnerable_ESC3_Templates"] = _state.ESC3VulnTemplates.Any()
                    ? _state.ESC3VulnTemplates.Select(BuildEsc3TemplateJson).ToArray()
                    : "No Vulnerable ESC3 Templates Found.";

                stelarkFindings["Vulnerable_ESC4_Templates"] = _state.ESC4VulnTemplates.Any()
                    ? _state.ESC4VulnTemplates.Select(BuildEsc4TemplateJson).ToArray()
                    : "No Vulnerable ESC4 Templates Found.";

                stelarkFindings["ESC6_Vulnerable_CAs"] = _state.ESC6VulnCAs.Any()
                    ? _state.ESC6VulnCAs.Select(BuildCAJson).ToArray()
                    : "No Certificate Authorities Vulnerable to ESC6 Were Found.";

                stelarkFindings["ESC7_Dangerous_CA_Permissions"] = _state.ESC7VulnCAPermissions.Any()
                    ? _state.ESC7VulnCAPermissions.Select(BuildCAPermissionJson).ToArray()
                    : "No Dangerous CA Permissions Related to ESC7 Were Found.";

                stelarkFindings["ESC8_Vulnerable_Endpoints"] = _state.ESC8VulnEndpoints.Any()
                    ? _state.ESC8VulnEndpoints.Select(BuildEndpointJson).ToArray()
                    : "No Endpoints Vulnerable Related to ESC8 Were Found.";

                stelarkFindings["Suspicious_ESC1_Certificates"] = _state.ESC1Certificates.Where(c => c.IsSuspicious).Any()
                    ? _state.ESC1Certificates.Where(c => c.IsSuspicious).Select(BuildCertificateJson).ToArray()
                    : "No Suspicious Certificates Issued by ESC1-Vulnerable Templates Were Identified.";

                stelarkFindings["Suspicious_ESC2_Certificates"] = _state.ESC2Certificates.Where(c => c.IsSuspicious).Any()
                    ? _state.ESC2Certificates.Where(c => c.IsSuspicious).Select(BuildCertificateJson).ToArray()
                    : "No Suspicious Certificates Issued by ESC2-Vulnerable Templates Were Identified.";

                stelarkFindings["Suspicious_ESC3_Certificates"] = _state.ESC3Certificates.Where(c => c.IsSuspicious).Any()
                    ? _state.ESC3Certificates.Where(c => c.IsSuspicious).Select(BuildCertificateJson).ToArray()
                    : "No Suspicious Certificates Issued by ESC3-Vulnerable Templates Were Identified.";

                stelarkFindings["Suspicious_ESC4_Certificates"] = _state.ESC4Certificates.Where(c => c.IsSuspicious).Any()
                    ? _state.ESC4Certificates.Where(c => c.IsSuspicious).Select(BuildCertificateJson).ToArray()
                    : "No Suspicious Certificates Issued by ESC4-Vulnerable Templates Were Identified.";

                stelarkFindings["Intense_Suspicious_Certificates"] = _state.IntenseUniqueCertificates.Any()
                    ? _state.IntenseUniqueCertificates.Select(BuildCertificateJson).ToArray()
                    : "No Suspicious Certificates Were Identified via Intense Mode.";
            }

            return result;
        }

        private object BuildTemplateJson(VulnerableTemplate template)
        {
            return new
            {
                TemplateName = template.CN,
                DisplayName = template.DisplayName,
                IsEnabled = template.IsEnabled,
                SuppliesSubject = template.SuppliesSubject,
                NoManagerApproval = template.NoManagerApproval,
                NoRASignature = template.NoRASignature,
                HasAuthEKU = template.HasAuthEKU,
                HasEnroll = template.HasEnroll,
                RiskyEnrollmentGroups = template.EnrollmentGroups.ToArray()
            };
        }

        private object BuildEsc2TemplateJson(VulnerableTemplate template)
        {
            return new
            {
                TemplateName = template.CN,
                DisplayName = template.DisplayName,
                IsEnabled = template.IsEnabled,
                NoManagerApproval = template.NoManagerApproval,
                NoRASignature = template.NoRASignature,
                HasAnyPurposeEKU = template.HasAnyPurposeEKU,
                HasNoEKU = template.HasNoEKU,
                HasEnroll = template.HasEnroll,
                RiskyEnrollmentGroups = template.EnrollmentGroups.ToArray()
            };
        }

        private object BuildEsc3TemplateJson(VulnerableTemplate template)
        {
            return new
            {
                TemplateName = template.CN,
                DisplayName = template.DisplayName,
                IsEnabled = template.IsEnabled,
                NoManagerApproval = template.NoManagerApproval,
                NoRASignature = template.NoRASignature,
                HasCertRequestAgentEKU = template.HasCertRequestAgentEKU,
                HasEnroll = template.HasEnroll,
                RiskyEnrollmentGroups = template.EnrollmentGroups.ToArray()
            };
        }

        private object BuildEsc4TemplateJson(VulnerableTemplate template)
        {
            return new
            {
                TemplateName = template.CN,
                DisplayName = template.DisplayName,
                RiskyGroups = template.RiskyGroups.Select(rg => new
                {
                    Group = rg.Group,
                    Permissions = rg.Rights
                }).ToArray()
            };
        }

        private object BuildCAJson(VulnerableCA ca)
        {
            return new
            {
                Server = ca.Server,
                VulnerabilityType = ca.VulnerabilityType,
                Edit_Flags = ca.EditFlags,
                HasEditfAttributeSubjectAltName2 = ca.HasEditfAttributeSubjectAltName2,
                Description = ca.Description
            };
        }

        private object BuildCAPermissionJson(VulnerableCAPermissions permission)
        {
            return new
            {
                Server = permission.Server,
                VulnerabilityType = permission.VulnerabilityType,
                Principal = permission.Principal,
                Permission = permission.Permission,
                Description = permission.Description,
                IsPrivilegedAccount = permission.IsPrivilegedAccount
            };
        }

        private object BuildEndpointJson(VulnerableEndpoint endpoint)
        {
            return new
            {
                Server = endpoint.Server,
                URL = endpoint.URL
            };
        }

        private object BuildCertificateJson(Certificate cert)
        {
            return new
            {
                RequestID = cert.RequestID.NormalizeRequestID(),
                Requester = cert.Requester,
                SubjectAlternativeName = cert.ContainsSAN ? cert.SANUPN : "N/A",
                IsSuspicious = cert.IsSuspicious,
                TemplateName = cert.Template,
                DispositionMsg = cert.DispositionMsg,
                SubmissionDate = cert.SubmissionDate,
                NotBefore = cert.NotBefore,
                NotAfter = cert.NotAfter,
                SerialNumber = cert.Serial,
                CertHash = cert.CertHash,
                Machine = cert.Machine,
                Process = cert.Process
            };
        }

        private async Task<string> RunProcessAndGetOutputAsync(string command, string args)
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = command,
                Arguments = args,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var process = Process.Start(startInfo);
            if (process == null)
            {
                return $"Error: Failed to start process '{command}'";
            }

            var output = await process.StandardOutput.ReadToEndAsync();
            var error = await process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync();

            return !string.IsNullOrEmpty(error) ? $"{output}\n\nERROR:\n{error}" : output;
        }

        private string GenerateHtmlReport(bool intenseOnly)
        {
            var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            var scanType = intenseOnly ? "Intense Scan" : (_state.IntenseScanRun ? "Full Scan" : "Standard Scan");
            var primaryCAName = DeterminePrimaryCAName();
            var multiCaFieldHtml = BuildAdditionalCaFieldHtml();

            var allCertificates = new List<Certificate>();
            var vulnerabilityStats = new Dictionary<string, int>();

            if (!intenseOnly)
            {
                allCertificates.AddRange(_state.ESC1Certificates.Where(c => c.IsSuspicious));
                allCertificates.AddRange(_state.ESC2Certificates.Where(c => c.IsSuspicious));
                allCertificates.AddRange(_state.ESC3Certificates.Where(c => c.IsSuspicious));
                allCertificates.AddRange(_state.ESC4Certificates.Where(c => c.IsSuspicious));

                vulnerabilityStats["ESC1"] = _state.ESC1VulnTemplates.Count;
                vulnerabilityStats["ESC2"] = _state.ESC2VulnTemplates.Count;
                vulnerabilityStats["ESC3"] = _state.ESC3VulnTemplates.Count;
                vulnerabilityStats["ESC4"] = _state.ESC4VulnTemplates.Count;
                vulnerabilityStats["ESC6"] = _state.ESC6VulnCAs.Count;
                vulnerabilityStats["ESC7"] = _state.ESC7VulnCAPermissions.Count;
                vulnerabilityStats["ESC8"] = _state.ESC8VulnEndpoints.Count;
            }

            allCertificates.AddRange(_state.IntenseUniqueCertificates);
            var totalVulnerabilities = vulnerabilityStats.Values.Sum();
            var totalCertificates = allCertificates.Count;

            var sourceOrder = new Dictionary<string, int>
            {
                { "ESC1", 1 },
                { "ESC2", 2 },
                { "ESC3", 3 },
                { "ESC4", 4 },
                { "INTENSE", 5 }
            };
            allCertificates = allCertificates
                .OrderBy(c => sourceOrder.ContainsKey(c.Source) ? sourceOrder[c.Source] : 99)
                .ThenBy(c => c.SubmissionDate)
                .ToList();

            var uniqueSources = allCertificates.Select(c => c.Source).Distinct().ToList();
            uniqueSources = uniqueSources.OrderBy(s => sourceOrder.ContainsKey(s) ? sourceOrder[s] : 99).ThenBy(s => s).ToList();

            var filterOptionsHtml = new System.Text.StringBuilder();
            filterOptionsHtml.AppendLine(@"<a onclick=""filterByESC('all')"" class=""dropdown-item active"">All</a>");
            
            foreach (var source in uniqueSources)
            {
                var displaySource = source == "INTENSE" ? "Intense" : source;
                var badgeClass = source.ToLower();
                filterOptionsHtml.AppendLine($@"<a onclick=""filterByESC('{source}')"" class=""dropdown-item"" data-source=""{source}""><span class=""badge {badgeClass}"">{displaySource}</span> {displaySource}</a>");
            }

            var certificateRowsHtml = new System.Text.StringBuilder();
            
            foreach (var cert in allCertificates)
            {
                var sourceClass = cert.Source.ToLower();
                
                var certJson = System.Text.Json.JsonSerializer.Serialize(new
                {
                    RequestID = cert.RequestID,
                    Source = cert.Source,
                    Requester = cert.Requester ?? "",
                    Principal = cert.Principal ?? "",
                    TemplateName = cert.TemplateName ?? "",
                    Template = cert.Template ?? cert.TemplateName ?? "",
                    DispositionMsg = cert.DispositionMsg ?? "Issued",
                    SubmissionDate = cert.SubmissionDate ?? "",
                    NotBefore = cert.NotBefore ?? "",
                    NotAfter = cert.NotAfter ?? "",
                    Serial = cert.Serial ?? "",
                    CertHash = cert.CertHash ?? "",
                    TemplateOID = cert.TemplateOID ?? "",
                    IsSuspicious = cert.IsSuspicious,
                    EKUs = cert.EKUs ?? new List<string>(),
                    ContainsSAN = cert.ContainsSAN,
                    SANUPN = cert.SANUPN ?? "",
                    Machine = cert.Machine ?? "",
                    Process = cert.Process ?? ""
                });
                
                var ekusList = cert.EKUs != null && cert.EKUs.Any() ? string.Join(", ", cert.EKUs) : "None";
                
                certificateRowsHtml.AppendLine($@"
                                <tr class=""cert-row"" onclick=""toggleDetails(this)"" data-cert-data='{System.Security.SecurityElement.Escape(certJson)}'>
                                    <td class=""expand-cell"">
                                        <div class=""expand-icon"">
                                            <svg xmlns=""http://www.w3.org/2000/svg"" width=""16"" height=""16"" viewBox=""0 0 24 24"" fill=""none"" stroke=""currentColor"" stroke-width=""2"" stroke-linecap=""round"" stroke-linejoin=""round"">
                                                <polyline points=""9 18 15 12 9 6""></polyline>
                                            </svg>
                                        </div>
                                    </td>
                                    <td><span class=""badge {sourceClass}"">{System.Security.SecurityElement.Escape(cert.Source)}</span></td>
                                    <td>{System.Security.SecurityElement.Escape(cert.RequestID)}</td>
                                    <td>{System.Security.SecurityElement.Escape(cert.Requester ?? "")}</td>
                                    <td>{System.Security.SecurityElement.Escape(cert.SANUPN ?? "")}</td>
                                    <td>{System.Security.SecurityElement.Escape(cert.Template ?? cert.TemplateName ?? "")}</td>
                                    <td>{System.Security.SecurityElement.Escape(cert.SubmissionDate ?? "")}</td>
                                    <td title=""{System.Security.SecurityElement.Escape(cert.DispositionMsg ?? "Issued")}"">{System.Security.SecurityElement.Escape(cert.DispositionMsg ?? "Issued")}</td>
                                </tr>
                                <tr class=""details-row"" style=""display: none;"">
                                    <td colspan=""8"">
                                        <div class=""details-content"">
                                            <div class=""details-grid"">
                                                <div class=""detail-item"">
                                                    <div class=""detail-label"">SERIAL NUMBER</div>
                                                    <div class=""detail-value"">{System.Security.SecurityElement.Escape(cert.Serial ?? "")}</div>
                                                </div>
                                                <div class=""detail-item"">
                                                    <div class=""detail-label"">CERTIFICATE HASH</div>
                                                    <div class=""detail-value"">{System.Security.SecurityElement.Escape(cert.CertHash ?? "")}</div>
                                                </div>
                                                <div class=""detail-item"">
                                                    <div class=""detail-label"">TEMPLATE OID</div>
                                                    <div class=""detail-value"">{System.Security.SecurityElement.Escape(cert.TemplateOID ?? "")}</div>
                                                </div>
                                                <div class=""detail-item"">
                                                    <div class=""detail-label"">NOT BEFORE</div>
                                                    <div class=""detail-value"">{System.Security.SecurityElement.Escape(cert.NotBefore ?? "")}</div>
                                                </div>
                                                <div class=""detail-item"">
                                                    <div class=""detail-label"">NOT AFTER</div>
                                                    <div class=""detail-value"">{System.Security.SecurityElement.Escape(cert.NotAfter ?? "")}</div>
                                                </div>
                                                <div class=""detail-item"">
                                                    <div class=""detail-label"">EKUS</div>
                                                    <div class=""detail-value"">{System.Security.SecurityElement.Escape(ekusList)}</div>
                                                </div>
                                                <div class=""detail-item"">
                                                    <div class=""detail-label"">PRINCIPAL</div>
                                                    <div class=""detail-value"">{System.Security.SecurityElement.Escape(cert.Principal ?? "")}</div>
                                                </div>
                                                <div class=""detail-item"">
                                                    <div class=""detail-label"">MACHINE</div>
                                                    <div class=""detail-value"">{System.Security.SecurityElement.Escape(cert.Machine ?? "")}</div>
                                                </div>
                                                <div class=""detail-item"">
                                                    <div class=""detail-label"">PROCESS</div>
                                                    <div class=""detail-value"">{System.Security.SecurityElement.Escape(cert.Process ?? "")}</div>
                                                </div>
                                            </div>
                                        </div>
                                    </td>
                                </tr>");
            }

            var templateCardsHtml = new System.Text.StringBuilder();

            var templateGroups = new List<(string Key, string Title, string Description, List<VulnerableTemplate> Templates)>();

            if (!intenseOnly)
            {
                templateGroups.Add(("ESC1", "SAN Spoofing Templates",
                    "These templates allow Subject Alternative Name (SAN) spoofing, enabling privilege escalation attacks.",
                    _state.ESC1VulnTemplates));

                templateGroups.Add(("ESC2", "Any Purpose EKU",
                    "Templates with 'Any Purpose' or 'No EKU' that can be abused for various attacks.",
                    _state.ESC2VulnTemplates));

                templateGroups.Add(("ESC3", "Enrollment Agent Templates",
                    "Templates with Certificate Request Agent EKU that enable privilege escalation.",
                    _state.ESC3VulnTemplates));

                templateGroups.Add(("ESC4", "Vulnerable ACL Templates",
                    "Templates with overly permissive access control lists.",
                    _state.ESC4VulnTemplates));
            }

            var sortedGroups = templateGroups.OrderByDescending(g => g.Templates.Count > 0).ThenBy(g => g.Key);

            foreach (var group in sortedGroups)
            {
                var count = group.Templates.Count;

                if (count > 0)
                {
                    var templateRows = new System.Text.StringBuilder();
                    foreach (var template in group.Templates)
                    {
                        var enabledBadge = template.IsEnabled ?
                            @"<span class=""badge enabled"">Enabled</span>" :
                            @"<span class=""badge disabled"">Disabled</span>";

                        string principals;
                        if (group.Key == "ESC4")
                        {
                            if (template.RiskyGroups != null && template.RiskyGroups.Count > 0)
                            {
                                principals = string.Join(", ", template.RiskyGroups.Select(rg => rg.Group));
                            }
                            else
                            {
                                principals = "None";
                            }
                        }
                        else
                        {
                            principals = (template.EnrollmentGroups != null && template.EnrollmentGroups.Count > 0) 
                                ? string.Join(", ", template.EnrollmentGroups) 
                                : "None";
                        }

                        templateRows.AppendLine($@"
                                <tr>
                                    <td>{System.Security.SecurityElement.Escape(template.DisplayName ?? "")}</td>
                                    <td>{System.Security.SecurityElement.Escape(template.CN ?? "")}</td>
                                    <td>{enabledBadge}</td>
                                    <td>{System.Security.SecurityElement.Escape(principals)}</td>
                                </tr>");
                    }

                    templateCardsHtml.AppendLine($@"
                <div class=""card"">
                    <div class=""card-header"">
                        <h3 class=""card-title""><span class=""badge {group.Key.ToLower()}"" style=""margin-right: 12px; font-size: 0.8rem; border-width: 1px;"">{group.Key}</span>{group.Title} ({count})</h3>
                    </div>
                    <p style=""color: #A0A0A0; margin-bottom: 16px;"">{group.Description}</p>
                    <div class=""table-container"">
                        <table>
                            <thead>
                                <tr>
                                    <th>Display Name</th>
                                    <th>CN</th>
                                    <th>Enabled</th>
                                    <th>Enrollment Groups</th>
                                </tr>
                            </thead>
                            <tbody>
                                {templateRows}
                            </tbody>
                        </table>
                    </div>
                </div>");
                }
                else
                {
                    templateCardsHtml.AppendLine($@"
                <div class=""card"">
                    <div class=""card-header"">
                        <h3 class=""card-title""><span class=""badge {group.Key.ToLower()}"" style=""margin-right: 12px; font-size: 0.8rem; border-width: 1px;"">{group.Key}</span>{group.Title} (0)</h3>
                    </div>
                    <p style=""color: #A0A0A0; margin-bottom: 16px;"">{group.Description}</p>
                    <div class=""empty-state"">
                        <div class=""empty-icon"">✓</div>
                        <h3>No {group.Key} Templates Found</h3>
                        <p>{GetEmptyStateMessage(group.Key)}</p>
                    </div>
                </div>");
                }
            }

            var caServerCount = _state.CAServerHostnames.Count > 0 ? _state.CAServerHostnames.Count : 0;
            var checksPerformed = GetChecksPerformedCount(intenseOnly); 

            var statsHtml = new System.Text.StringBuilder();
            statsHtml.AppendLine($@"
                    <div class=""stat-card"">
                        <div class=""stat-card-header"">
                            <div class=""stat-icon red"">⚠️</div>
                            <div class=""stat-number"">{totalVulnerabilities}</div>
                        </div>
                        <div class=""stat-label"">Total Vulnerabilities</div>
                    </div>
                    <div class=""stat-card"">
                        <div class=""stat-card-header"">
                            <div class=""stat-icon orange"">📋</div>
                            <div class=""stat-number"">{totalCertificates}</div>
                        </div>
                        <div class=""stat-label"">Suspicious Certificates</div>
                    </div>
                    <div class=""stat-card"">
                        <div class=""stat-card-header"">
                            <div class=""stat-icon blue"">🖥️</div>
                            <div class=""stat-number"">{caServerCount}</div>
                        </div>
                        <div class=""stat-label"">CA Servers Found</div>
                    </div>
                    <div class=""stat-card"">
                        <div class=""stat-card-header"">
                            <div class=""stat-icon green"">✓</div>
                            <div class=""stat-number"">{checksPerformed}</div>
                        </div>
                        <div class=""stat-label"">Checks Performed</div>
                    </div>");

            return GenerateHtmlStructure(timestamp, scanType, primaryCAName, statsHtml.ToString(), certificateRowsHtml.ToString(), templateCardsHtml.ToString(), totalCertificates, vulnerabilityStats, multiCaFieldHtml, filterOptionsHtml.ToString());
        }

        private string DeterminePrimaryCAName()
        {
            if (!string.IsNullOrWhiteSpace(_state.LocalCAServerName))
            {
                return _state.LocalCAServerName;
            }

            if (_state.CAServerHostnames.Count == 1)
            {
                return _state.CAServerHostnames[0];
            }

            if (_state.IsLocalCAServer)
            {
                return Environment.MachineName;
            }

            if (!_state.FoundCAServers)
            {
                return "No CA Infrastructure Detected";
            }

            if (_state.CAServerHostnames.Count > 0)
            {
                return "Not running on CA server";
            }

            return "Not Available";
        }

        private string BuildAdditionalCaFieldHtml()
        {
            if (_state.CAServerHostnames.Count <= 1)
            {
                return string.Empty;
            }

            var builder = new System.Text.StringBuilder();
            builder.AppendLine(@"                        <div class=""info-item"">");
            builder.AppendLine(@"                            <div class=""info-label"">CA Servers</div>");
            builder.AppendLine(@"                            <div class=""info-value"">");
            builder.AppendLine(@"                                <div class=""ca-list"">");

            foreach (var caServer in _state.CAServerHostnames)
            {
                var safeName = WebUtility.HtmlEncode(caServer);
                builder.AppendLine($@"                                    <span class=""ca-pill"">{safeName}</span>");
            }

            builder.AppendLine(@"                                </div>");
            builder.AppendLine(@"                            </div>");
            builder.AppendLine(@"                        </div>");

            return builder.ToString();
        }

        private string GetEmptyStateMessage(string escType)
        {
            return escType switch
            {
                "ESC1" => "No templates with Subject Alternative Name (SAN) spoofing capabilities were detected. This is a positive security finding.",
                "ESC2" => "No templates with 'Any Purpose' or 'No EKU' were detected. Your template EKU configurations appear properly restricted.",
                "ESC3" => "No templates with Certificate Request Agent EKU were detected in this environment. This is a positive security finding.",
                "ESC4" => "No templates with vulnerable ACL configurations were detected. Your template permissions appear properly configured.",
                _ => "No vulnerabilities of this type were detected in your environment."
            };
        }
        private string GenerateHtmlStructure(string timestamp, string scanType, string primaryCAName, string statsHtml, string certificateRowsHtml, string templateCardsHtml, int totalCertificates, Dictionary<string, int> vulnerabilityStats, string multiCaFieldHtml, string filterOptionsHtml)
        {
            var vulnDescriptions = new Dictionary<string, string>
            {
                { "ESC1", "SAN Spoofing Templates" },
                { "ESC2", "Any Purpose EKU" },
                { "ESC3", "Enrollment Agent" },
                { "ESC4", "Vulnerable ACL" },
                { "ESC6", "EDITF_ATTRIBUTESSUBJECTALTNAME2" },
                { "ESC7", "Vulnerable CA Permissions" },
                { "ESC8", "NTLM Relay to AD CS HTTP Endpoints" },
                { "INTENSE", "Intense Analysis Findings" }
            };

            var breakdownRowsHtml = new System.Text.StringBuilder();
            var sortedKeys = vulnerabilityStats.Keys.OrderBy(k => k).ToList();

            foreach (var key in sortedKeys)
            {
                if (vulnerabilityStats[key] > 0)
                {
                    var desc = vulnDescriptions.ContainsKey(key) ? vulnDescriptions[key] : key;
                    var badgeClass = key.ToLower();
                    breakdownRowsHtml.AppendLine($@"
                                <tr>
                                    <td><span class=""badge {badgeClass}"">{key}</span></td>
                                    <td>{desc}</td>
                                    <td>{vulnerabilityStats[key]}</td>
                                </tr>");
                }
            }

        var svgOverview = @"<svg xmlns=""http://www.w3.org/2000/svg"" width=""20"" height=""20"" viewBox=""0 0 24 24"" fill=""none"" stroke=""currentColor"" stroke-width=""2"" stroke-linecap=""round"" stroke-linejoin=""round""><rect width=""7"" height=""9"" x=""3"" y=""3"" rx=""1""/><rect width=""7"" height=""5"" x=""14"" y=""3"" rx=""1""/><rect width=""7"" height=""9"" x=""14"" y=""12"" rx=""1""/><rect width=""7"" height=""5"" x=""3"" y=""16"" rx=""1""/></svg>";
            var svgTemplates = @"<svg xmlns=""http://www.w3.org/2000/svg"" width=""20"" height=""20"" viewBox=""0 0 24 24"" fill=""none"" stroke=""currentColor"" stroke-width=""2"" stroke-linecap=""round"" stroke-linejoin=""round""><path d=""M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10""/><path d=""M12 8v4""/><path d=""M12 16h.01""/></svg>";
            var svgCerts = @"<svg xmlns=""http://www.w3.org/2000/svg"" width=""20"" height=""20"" viewBox=""0 0 24 24"" fill=""none"" stroke=""currentColor"" stroke-width=""2"" stroke-linecap=""round"" stroke-linejoin=""round""><path d=""M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z""/><polyline points=""14 2 14 8 20 8""/><path d=""M12 13v-2""/><path d=""M12 17h.01""/><path d=""M12 9h.01""/></svg>";
            var svgMenu = @"<svg xmlns=""http://www.w3.org/2000/svg"" width=""20"" height=""20"" viewBox=""0 0 24 24"" fill=""none"" stroke=""currentColor"" stroke-width=""2"" stroke-linecap=""round"" stroke-linejoin=""round""><rect width=""18"" height=""18"" x=""3"" y=""3"" rx=""2"" ry=""2""/><path d=""M9 3v18""/></svg>";
        var svgMoon = @"<svg xmlns=""http://www.w3.org/2000/svg"" width=""20"" height=""20"" viewBox=""0 0 24 24"" fill=""none"" stroke=""currentColor"" stroke-width=""2"" stroke-linecap=""round"" stroke-linejoin=""round""><path d=""M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z""/></svg>";
        var svgSun = @"<svg xmlns=""http://www.w3.org/2000/svg"" width=""20"" height=""20"" viewBox=""0 0 24 24"" fill=""none"" stroke=""currentColor"" stroke-width=""2"" stroke-linecap=""round"" stroke-linejoin=""round""><circle cx=""12"" cy=""12"" r=""5""/><path d=""M12 1v2""/><path d=""M12 21v2""/><path d=""M4.22 4.22l1.42 1.42""/><path d=""M18.36 18.36l1.42 1.42""/><path d=""M1 12h2""/><path d=""M21 12h2""/><path d=""M4.22 19.78l1.42-1.42""/><path d=""M18.36 5.64l1.42-1.42""/></svg>";
            
            statsHtml = statsHtml.Replace("⚠️", @"<svg xmlns=""http://www.w3.org/2000/svg"" width=""24"" height=""24"" viewBox=""0 0 24 24"" fill=""none"" stroke=""currentColor"" stroke-width=""2"" stroke-linecap=""round"" stroke-linejoin=""round""><path d=""m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z""/><path d=""M12 9v4""/><path d=""M12 17h.01""/></svg>");
            statsHtml = statsHtml.Replace("📋", @"<svg xmlns=""http://www.w3.org/2000/svg"" width=""24"" height=""24"" viewBox=""0 0 24 24"" fill=""none"" stroke=""currentColor"" stroke-width=""2"" stroke-linecap=""round"" stroke-linejoin=""round""><path d=""M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z""/><polyline points=""14 2 14 8 20 8""/><path d=""M12 13v-1""/><path d=""M12 17v-1""/><path d=""M12 9v-1""/></svg>");
            statsHtml = statsHtml.Replace("🖥️", @"<svg xmlns=""http://www.w3.org/2000/svg"" width=""24"" height=""24"" viewBox=""0 0 24 24"" fill=""none"" stroke=""currentColor"" stroke-width=""2"" stroke-linecap=""round"" stroke-linejoin=""round""><rect width=""20"" height=""8"" x=""2"" y=""2"" rx=""2"" ry=""2""/><rect width=""20"" height=""8"" x=""2"" y=""14"" rx=""2"" ry=""2""/><line x1=""6"" x2=""6.01"" y1=""6"" y2=""6""/><line x1=""6"" x2=""6.01"" y1=""18"" y2=""18""/></svg>");
            statsHtml = statsHtml.Replace("✓", @"<svg xmlns=""http://www.w3.org/2000/svg"" width=""24"" height=""24"" viewBox=""0 0 24 24"" fill=""none"" stroke=""currentColor"" stroke-width=""2"" stroke-linecap=""round"" stroke-linejoin=""round""><path d=""M22 11.08V12a10 10 0 1 1-5.93-9.14""/><polyline points=""22 4 12 14.01 9 11.01""/></svg>");

            var shouldHideTabs = !_state.IsLocalCAServer;
            var navItemsHtml = shouldHideTabs ? "" : $@"
                <a class=""nav-item"" onclick=""showTab('vulnerabilities')"">
                    <span class=""nav-icon"">{svgTemplates}</span>
                    <span>Vulnerabilities</span>
                    <span class=""nav-badge"">{(vulnerabilityStats.Values.Sum())}</span>
                </a>
                <a class=""nav-item"" onclick=""showTab('certificates')"">
                    <span class=""nav-icon"">{svgCerts}</span>
                    <span>Certificates</span>
                    <span class=""nav-badge"">{totalCertificates}</span>
                </a>";

            var tabsContentHtml = shouldHideTabs ? "" : $@"
            <div id=""vulnerabilities"" class=""tab-content"">
                <div class=""content-header"">
                    <h2>Vulnerabilities</h2>
                    <p>Security misconfigurations in certificate templates and CA infrastructure that enable privilege escalation</p>
                </div>

                {templateCardsHtml}
                {GenerateCAVulnerabilitiesContent()}
            </div>

            <!-- Suspicious Certificates Tab -->
            <div id=""certificates"" class=""tab-content"">
                <div class=""content-header"">
                    <h2>Suspicious Certificates</h2>
                    <p>Certificates issued from vulnerable templates that may indicate exploitation</p>
                </div>

                <div class=""card"">
                    <div class=""card-header"">
                        <h3 class=""card-title"">Certificate Analysis Results ({totalCertificates} Certificates)</h3>
                        {(totalCertificates > 0 ? $@"<div style=""display: flex; gap: 8px;"">
                            <div class=""dropdown"">
                                <button class=""btn dropdown-toggle"" onclick=""toggleDropdown('filterDropdown')"">
                                    <svg xmlns=""http://www.w3.org/2000/svg"" width=""16"" height=""16"" viewBox=""0 0 24 24"" fill=""none"" stroke=""currentColor"" stroke-width=""2"" stroke-linecap=""round"" stroke-linejoin=""round"" style=""margin-right: 6px;""><polygon points=""22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3""></polygon></svg>
                                    Filter
                                </button>
                                <div id=""filterDropdown"" class=""dropdown-menu"">
                                    {filterOptionsHtml}
                                </div>
                            </div>
                            <div class=""dropdown"">
                                <button class=""btn dropdown-toggle"" onclick=""toggleDropdown('exportDropdown')"">
                                    <svg xmlns=""http://www.w3.org/2000/svg"" width=""16"" height=""16"" viewBox=""0 0 24 24"" fill=""none"" stroke=""currentColor"" stroke-width=""2"" stroke-linecap=""round"" stroke-linejoin=""round"" style=""margin-right: 6px;""><path d=""M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4""></path><polyline points=""7 10 12 15 17 10""></polyline><line x1=""12"" y1=""15"" x2=""12"" y2=""3""></line></svg>
                                    Export
                                </button>
                                <div id=""exportDropdown"" class=""dropdown-menu"">
                                    <a onclick=""exportCertificates('csv')"" class=""dropdown-item"">
                                        <svg xmlns=""http://www.w3.org/2000/svg"" width=""14"" height=""14"" viewBox=""0 0 24 24"" fill=""none"" stroke=""currentColor"" stroke-width=""2"" stroke-linecap=""round"" stroke-linejoin=""round"" style=""margin-right: 8px;""><path d=""M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z""></path><polyline points=""14 2 14 8 20 8""></polyline><line x1=""16"" y1=""13"" x2=""8"" y2=""13""></line><line x1=""16"" y1=""17"" x2=""8"" y2=""17""></line><polyline points=""10 9 9 9 8 9""></polyline></svg>
                                        Export as CSV
                                    </a>
                                    <a onclick=""exportCertificates('json')"" class=""dropdown-item"">
                                        <svg xmlns=""http://www.w3.org/2000/svg"" width=""14"" height=""14"" viewBox=""0 0 24 24"" fill=""none"" stroke=""currentColor"" stroke-width=""2"" stroke-linecap=""round"" stroke-linejoin=""round"" style=""margin-right: 8px;""><path d=""M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z""></path><polyline points=""14 2 14 8 20 8""></polyline><line x1=""16"" y1=""13"" x2=""8"" y2=""13""></line><line x1=""16"" y1=""17"" x2=""8"" y2=""17""></line><polyline points=""10 9 9 9 8 9""></polyline></svg>
                                        Export as JSON
                                    </a>
                                </div>
                            </div>
                        </div>" : "")}
                    </div>
                    {(totalCertificates > 0 ? $@"
                    <div class=""table-container"">
                        <table id=""certificatesTable"">
                            <thead>
                                <tr>
                                    <th style=""width: 40px;""></th>
                                    <th class=""sortable-header"" onclick=""sortTable('Source', this)"">
                                        <div class=""header-content"">
                                            Source
                                            <div class=""sort-icon"">
                                                <svg class=""up"" width=""10"" height=""6"" viewBox=""0 0 10 6"" fill=""none"" xmlns=""http://www.w3.org/2000/svg""><path d=""M1 5L5 1L9 5"" stroke=""currentColor"" stroke-width=""1.5"" stroke-linecap=""round"" stroke-linejoin=""round""/></svg>
                                                <svg class=""down"" width=""10"" height=""6"" viewBox=""0 0 10 6"" fill=""none"" xmlns=""http://www.w3.org/2000/svg"" style=""margin-top: 2px""><path d=""M1 1L5 5L9 1"" stroke=""currentColor"" stroke-width=""1.5"" stroke-linecap=""round"" stroke-linejoin=""round""/></svg>
                                            </div>
                                        </div>
                                    </th>
                                    <th class=""sortable-header"" onclick=""sortTable('RequestID', this)"">
                                        <div class=""header-content"">
                                            Request ID
                                            <div class=""sort-icon"">
                                                <svg class=""up"" width=""10"" height=""6"" viewBox=""0 0 10 6"" fill=""none"" xmlns=""http://www.w3.org/2000/svg""><path d=""M1 5L5 1L9 5"" stroke=""currentColor"" stroke-width=""1.5"" stroke-linecap=""round"" stroke-linejoin=""round""/></svg>
                                                <svg class=""down"" width=""10"" height=""6"" viewBox=""0 0 10 6"" fill=""none"" xmlns=""http://www.w3.org/2000/svg"" style=""margin-top: 2px""><path d=""M1 1L5 5L9 1"" stroke=""currentColor"" stroke-width=""1.5"" stroke-linecap=""round"" stroke-linejoin=""round""/></svg>
                                            </div>
                                        </div>
                                    </th>
                                    <th class=""sortable-header"" onclick=""sortTable('Requester', this)"">
                                        <div class=""header-content"">
                                            Requester
                                            <div class=""sort-icon"">
                                                <svg class=""up"" width=""10"" height=""6"" viewBox=""0 0 10 6"" fill=""none"" xmlns=""http://www.w3.org/2000/svg""><path d=""M1 5L5 1L9 5"" stroke=""currentColor"" stroke-width=""1.5"" stroke-linecap=""round"" stroke-linejoin=""round""/></svg>
                                                <svg class=""down"" width=""10"" height=""6"" viewBox=""0 0 10 6"" fill=""none"" xmlns=""http://www.w3.org/2000/svg"" style=""margin-top: 2px""><path d=""M1 1L5 5L9 1"" stroke=""currentColor"" stroke-width=""1.5"" stroke-linecap=""round"" stroke-linejoin=""round""/></svg>
                                            </div>
                                        </div>
                                    </th>
                                    <th class=""sortable-header"" onclick=""sortTable('SANUPN', this)"">
                                        <div class=""header-content"">
                                            SAN/UPN
                                            <div class=""sort-icon"">
                                                <svg class=""up"" width=""10"" height=""6"" viewBox=""0 0 10 6"" fill=""none"" xmlns=""http://www.w3.org/2000/svg""><path d=""M1 5L5 1L9 5"" stroke=""currentColor"" stroke-width=""1.5"" stroke-linecap=""round"" stroke-linejoin=""round""/></svg>
                                                <svg class=""down"" width=""10"" height=""6"" viewBox=""0 0 10 6"" fill=""none"" xmlns=""http://www.w3.org/2000/svg"" style=""margin-top: 2px""><path d=""M1 1L5 5L9 1"" stroke=""currentColor"" stroke-width=""1.5"" stroke-linecap=""round"" stroke-linejoin=""round""/></svg>
                                            </div>
                                        </div>
                                    </th>
                                    <th class=""sortable-header"" onclick=""sortTable('Template', this)"">
                                        <div class=""header-content"">
                                            Template
                                            <div class=""sort-icon"">
                                                <svg class=""up"" width=""10"" height=""6"" viewBox=""0 0 10 6"" fill=""none"" xmlns=""http://www.w3.org/2000/svg""><path d=""M1 5L5 1L9 5"" stroke=""currentColor"" stroke-width=""1.5"" stroke-linecap=""round"" stroke-linejoin=""round""/></svg>
                                                <svg class=""down"" width=""10"" height=""6"" viewBox=""0 0 10 6"" fill=""none"" xmlns=""http://www.w3.org/2000/svg"" style=""margin-top: 2px""><path d=""M1 1L5 5L9 1"" stroke=""currentColor"" stroke-width=""1.5"" stroke-linecap=""round"" stroke-linejoin=""round""/></svg>
                                            </div>
                                        </div>
                                    </th>
                                    <th class=""sortable-header"" onclick=""sortTable('SubmissionDate', this)"">
                                        <div class=""header-content"">
                                            Submitted
                                            <div class=""sort-icon"">
                                                <svg class=""up"" width=""10"" height=""6"" viewBox=""0 0 10 6"" fill=""none"" xmlns=""http://www.w3.org/2000/svg""><path d=""M1 5L5 1L9 5"" stroke=""currentColor"" stroke-width=""1.5"" stroke-linecap=""round"" stroke-linejoin=""round""/></svg>
                                                <svg class=""down"" width=""10"" height=""6"" viewBox=""0 0 10 6"" fill=""none"" xmlns=""http://www.w3.org/2000/svg"" style=""margin-top: 2px""><path d=""M1 1L5 5L9 1"" stroke=""currentColor"" stroke-width=""1.5"" stroke-linecap=""round"" stroke-linejoin=""round""/></svg>
                                            </div>
                                        </div>
                                    </th>
                                    <th class=""sortable-header"" onclick=""sortTable('DispositionMsg', this)"">
                                        <div class=""header-content"">
                                            Status
                                            <div class=""sort-icon"">
                                                <svg class=""up"" width=""10"" height=""6"" viewBox=""0 0 10 6"" fill=""none"" xmlns=""http://www.w3.org/2000/svg""><path d=""M1 5L5 1L9 5"" stroke=""currentColor"" stroke-width=""1.5"" stroke-linecap=""round"" stroke-linejoin=""round""/></svg>
                                                <svg class=""down"" width=""10"" height=""6"" viewBox=""0 0 10 6"" fill=""none"" xmlns=""http://www.w3.org/2000/svg"" style=""margin-top: 2px""><path d=""M1 1L5 5L9 1"" stroke=""currentColor"" stroke-width=""1.5"" stroke-linecap=""round"" stroke-linejoin=""round""/></svg>
                                            </div>
                                        </div>
                                    </th>
                                </tr>
                            </thead>
                            <tbody>
                                {certificateRowsHtml}
                            </tbody>
                        </table>
                    </div>
                    <div id=""certPagination"" class=""pagination-container""></div>" : $@"
                    <div class=""empty-state"">
                        <div class=""empty-icon"">✓</div>
                        <h3>No Suspicious Certificates Found</h3>
                        <p>No certificates with Subject Alternative Names (SAN) were detected from any certificate templates. This indicates that no suspicious certificate activity was identified during the scan.</p>
                    </div>")}
                </div>
            </div>";

            return $@"<!DOCTYPE html>
<html lang=""en"" data-theme=""nebula"">
<head>
    <meta charset=""UTF-8"">
    <meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">
    <title>Stelark AD CSSecurity Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        /* Sortable Headers */
        th.sortable-header {{
            cursor: pointer;
            user-select: none;
            position: relative;
        }}

        th.sortable-header:hover {{
            background-color: var(--bg-hover);
        }}

        .header-content {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        .sort-icon {{
            display: flex;
            flex-direction: column;
            opacity: 0.3;
            transition: opacity 0.2s;
        }}

        th[data-sort-dir=""asc""] .sort-icon .up {{
            opacity: 1;
        }}
        
        th[data-sort-dir=""asc""] .sort-icon .down {{
            opacity: 0.3;
        }}

        th[data-sort-dir=""desc""] .sort-icon .down {{
            opacity: 1;
        }}

        th[data-sort-dir=""desc""] .sort-icon .up {{
            opacity: 0.3;
        }}

        /* Theme Variables - Nebula Mode (Default) */
        :root[data-theme=""nebula""] {{
            --bg-primary: #060A13;
            --bg-secondary: rgba(7, 11, 25, 0.95);
            --bg-card: #090E19;
            --bg-table: #090E19;
            --bg-table-header: #0C1423;
            --bg-hover: rgba(124, 164, 255, 0.12);
            --bg-input: #0B1422;
            --bg-inner-card: #131C2B;
            --bg-sidebar: #060A13;
            --bg-expanded-row: #0D1321;
            --text-primary: #EEF2FF;
            --text-secondary: #B7C5E5;
            --text-tertiary: #7C8DB8;
            --text-white: #FFFFFF;
            --border-primary: rgba(149, 173, 228, 0.22);
            --border-secondary: rgba(62, 80, 115, 0.45);
            --border-hover: rgba(124, 164, 255, 0.5);
            --accent-primary: #8AB4FF;
            --accent-muted: rgba(138, 180, 255, 0.2);
            --accent-border: rgba(138, 180, 255, 0.35);
            --link-color: #A8C7FF;
            --link-hover: #C6DCFF;
            --details-row-bg: #0D1321;
            --details-content-bg: #0D1321;
        }}

        /* Theme Variables - White Mode */
        :root[data-theme=""white""] {{
            --bg-primary: #F5F5F5;
            --bg-secondary: rgba(255, 255, 255, 0.9);
            --bg-card: rgba(255, 255, 255, 0.8);
            --bg-table: rgba(250, 250, 250, 0.8);
            --bg-table-header: rgba(240, 240, 240, 0.9);
            --bg-hover: rgba(230, 230, 230, 0.6);
            --bg-input: rgba(255, 255, 255, 0.8);
            --bg-inner-card: rgba(245, 245, 245, 0.95);
            --bg-sidebar: rgba(255, 255, 255, 0.95);
            --bg-expanded-row: rgba(230, 230, 230, 0.8);
            --text-primary: #1F1F1F;
            --text-secondary: #4A4A4A;
            --text-tertiary: #737373;
            --text-white: #1F1F1F;
            --border-primary: rgba(0, 0, 0, 0.12);
            --border-secondary: rgba(0, 0, 0, 0.08);
            --border-hover: rgba(0, 0, 0, 0.18);
            --accent-primary: #2563EB;
            --accent-muted: rgba(37, 99, 235, 0.12);
            --accent-border: rgba(37, 99, 235, 0.2);
            --link-color: #2563EB;
            --link-hover: #1D4ED8;
            --details-row-bg: rgba(245, 245, 245, 0.8);
            --details-content-bg: rgba(255, 255, 255, 0.9);
        }}

        body {{
            font-family: 'Segoe UI Variable', 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
            overflow-x: hidden;
            transition: background-color 0.3s ease, color 0.3s ease;
        }}

        .app-container {{
            display: flex;
            min-height: 100vh;
            transition: all 0.3s ease;
        }}

        /* Sidebar Styles */
        .sidebar {{
            width: 280px;
            background: var(--bg-sidebar);
            backdrop-filter: blur(40px) saturate(180%);
            -webkit-backdrop-filter: blur(40px) saturate(180%);
            border-right: 1px solid var(--border-primary);
            padding: 24px 0;
            position: fixed;
            height: 100vh;
            overflow-y: auto;
            z-index: 1000;
            transition: all 0.3s ease;
            display: flex;
            flex-direction: column;
        }}
        
        .sidebar.collapsed {{
            width: 80px;
            padding: 24px 0;
        }}

        .sidebar-header {{
            padding: 0 24px 24px 24px;
            border-bottom: 1px solid var(--border-primary);
            transition: all 0.3s ease;
        }}

        .sidebar.collapsed .sidebar-header {{
            padding: 0;
            border-bottom: none;
            margin-bottom: 12px;
            display: flex;
            justify-content: center;
        }}

        .sidebar-header h1 {{
            color: var(--text-white);
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 8px;
            letter-spacing: -0.02em;
            white-space: nowrap;
        }}
        
        .sidebar.collapsed .sidebar-header h1 {{
            display: none;
        }}

        .sidebar-header .subtitle {{
            color: #6B6B6B;
            font-size: 0.9rem;
            font-style: italic;
            white-space: nowrap;
        }}
        
        .sidebar.collapsed .sidebar-header .subtitle {{
            display: none;
        }}

        .nav-section {{
            margin-top: 24px;
        }}
        
        .sidebar.collapsed .nav-section {{
            margin-top: 12px;
        }}

        .nav-section-title {{
            padding: 6px 24px;
            color: #6B6B6B;
            font-size: 0.8rem;
            font-weight: 600;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            white-space: nowrap;
        }}
        
        .sidebar.collapsed .nav-section-title {{
            display: none;
        }}

        .nav-item {{
            display: flex;
            align-items: center;
            padding: 12px 24px;
            color: var(--text-secondary);
            text-decoration: none;
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
            cursor: pointer;
            border-left: 3px solid transparent;
            gap: 12px;
            white-space: nowrap;
        }}
        
        .sidebar.collapsed .nav-item {{
            padding: 12px 0;
            justify-content: center;
            border-left: 3px solid transparent;
        }}

        .nav-item:hover {{
            background: var(--bg-hover);
            color: var(--text-primary);
        }}

        .nav-item.active {{
            background: var(--accent-muted);
            color: var(--accent-primary);
            border-left-color: var(--accent-primary);
        }}
        
        .sidebar.collapsed .nav-item.active {{
            border-left-color: transparent;
            border-right: 3px solid var(--accent-primary); /* Move active border to right when collapsed */
        }}
        
        .nav-item span:not(.nav-icon) {{
            transition: opacity 0.2s ease;
        }}
        
        .sidebar.collapsed .nav-item span:not(.nav-icon) {{
            display: none;
        }}

        .nav-badge {{
            margin-left: auto;
            background: rgba(239, 68, 68, 0.15);
            color: #F87171;
            border: 1px solid rgba(239, 68, 68, 0.3);
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.7rem;
            font-weight: 600;
        }}
        
        .sidebar.collapsed .nav-badge {{
            display: none;
        }}

        /* Main Content Area */
        .main-content {{
            flex: 1;
            margin-left: 280px;
            padding: 32px;
            max-width: calc(100% - 280px);
            transition: all 0.3s ease;
        }}
        
        .main-content.expanded {{
            margin-left: 80px;
            max-width: calc(100% - 80px);
        }}

        .top-bar {{
            background: var(--bg-card);
            backdrop-filter: blur(40px) saturate(180%);
            -webkit-backdrop-filter: blur(40px) saturate(180%);
            border: 1px solid var(--border-primary);
            border-radius: 12px;
            padding: 20px 28px;
            margin-bottom: 32px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            transition: background-color 0.3s ease, border-color 0.3s ease;
            gap: 16px;
        }}

        .toggle-sidebar-btn {{
            background: transparent;
            border: none;
            color: var(--text-secondary);
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 8px;
            border-radius: 6px;
            transition: all 0.2s ease;
        }}
        
        .toggle-sidebar-btn:hover {{
            background: var(--bg-hover);
            color: var(--text-primary);
        }}

        .search-bar {{
            flex: 1;
            max-width: 600px;
        }}

        .search-input {{
            width: 100%;
            padding: 12px 20px 12px 44px;
            background: var(--bg-input);
            border: 1px solid var(--border-primary);
            border-radius: 24px;
            font-size: 14px;
            color: var(--text-primary);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            background-image: url(""data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='20' height='20' viewBox='0 0 24 24' fill='none' stroke='%236B6B6B' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Ccircle cx='11' cy='11' r='8'%3E%3C/circle%3E%3Cpath d='m21 21-4.35-4.35'%3E%3C/path%3E%3C/svg%3E"");
            background-repeat: no-repeat;
            background-position: 16px center;
        }}

        .search-input::placeholder {{
            color: var(--text-tertiary);
        }}

        .search-input:focus {{
            outline: none;
            border-color: var(--accent-primary);
            background-color: var(--bg-input);
            box-shadow: 0 0 0 3px var(--accent-muted);
        }}

        .theme-toggle {{
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background: var(--bg-input);
            border: 1px solid var(--border-primary);
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: all 0.3s ease;
            margin-left: auto; /* Push to right if needed */
            font-size: 20px;
            color: var(--text-secondary);
        }}

        .theme-toggle:hover {{
            background: var(--bg-hover);
            border-color: var(--border-hover);
            transform: scale(1.05);
            color: var(--text-primary);
        }}
        
        /* Helper for Icons */
        .nav-icon {{
            display: flex;
            align-items: center;
            justify-content: center;
        }}

        .content-header {{
            margin-bottom: 32px;
        }}

        .content-header h2 {{
            color: var(--text-white);
            font-size: 2rem;
            font-weight: 600;
            margin-bottom: 8px;
            letter-spacing: -0.02em;
        }}

        .content-header p {{
            color: var(--text-secondary);
            font-size: 1rem;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }}

        .stat-card {{
            background: var(--bg-card);
            backdrop-filter: blur(40px) saturate(180%);
            -webkit-backdrop-filter: blur(40px) saturate(180%);
            border: 1px solid var(--border-primary);
            border-radius: 12px;
            padding: 24px;
            box-shadow: none;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            display: flex;
            flex-direction: column;
            align-items: flex-start;
        }}

        .stat-card:hover {{
            transform: translateY(-2px);
            box-shadow: none;
            border-color: var(--border-hover);
            background: var(--bg-hover);
        }}

        .stat-card-header {{
            display: flex;
            align-items: center;
            justify-content: flex-start;
            gap: 12px;
            margin-bottom: 12px;
            margin-left: 0;
            margin-right: 0;
            padding: 0;
        }}

        .stat-icon {{
            width: 40px;
            height: 40px;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 20px;
            flex-shrink: 0;
            line-height: 1;
            margin: 0;
            padding: 0;
        }}

        .stat-icon.red {{ background: rgba(239, 68, 68, 0.15); color: #F87171; }}
        .stat-icon.orange {{ background: rgba(251, 146, 60, 0.15); color: #FB923C; }}
        .stat-icon.blue {{ background: var(--accent-muted); color: var(--accent-primary); }}
        .stat-icon.green {{ background: rgba(34, 197, 94, 0.15); color: #4ADE80; }}

        .stat-number {{
            font-size: 2rem;
            font-weight: 600;
            color: var(--text-white);
            margin: 0;
            padding: 0;
            line-height: 1;
            display: flex;
            align-items: center;
        }}

        .stat-label {{
            color: var(--text-tertiary);
            font-size: 0.875rem;
            font-weight: 500;
            line-height: 1.4;
            margin: 0;
            padding: 0;
            display: block;
        }}

        .card {{
            background: var(--bg-card);
            backdrop-filter: blur(40px) saturate(180%);
            -webkit-backdrop-filter: blur(40px) saturate(180%);
            border: 1px solid var(--border-primary);
            border-radius: 12px;
            padding: 28px;
            margin-bottom: 24px;
            box-shadow: none;
            transition: background-color 0.3s ease, border-color 0.3s ease;
        }}

        .card-header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 20px;
        }}

        .card-title {{
            color: var(--text-white);
            font-size: 1.25rem;
            font-weight: 600;
            letter-spacing: -0.01em;
        }}

        .badge {{
            display: inline-block;
            padding: 6px 14px;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 600;
            letter-spacing: 0.03em;
            border: 1px solid;
        }}

        .badge.esc1 {{ background: rgba(239, 68, 68, 0.15); color: #F87171; border-color: rgba(239, 68, 68, 0.3); }}
        .badge.esc2 {{ background: rgba(251, 146, 60, 0.15); color: #FB923C; border-color: rgba(251, 146, 60, 0.3); }}
        .badge.esc3 {{ background: rgba(168, 85, 247, 0.15); color: #C084FC; border-color: rgba(168, 85, 247, 0.3); }}
        .badge.esc4 {{ background: rgba(234, 179, 8, 0.15); color: #FBBF24; border-color: rgba(234, 179, 8, 0.3); }}
        .badge.esc6 {{ background: rgba(34, 197, 94, 0.15); color: #4ADE80; border-color: rgba(34, 197, 94, 0.3); }}
        .badge.esc7 {{ background: rgba(20, 184, 166, 0.15); color: #2DD4BF; border-color: rgba(20, 184, 166, 0.3); }}
        .badge.esc8 {{ background: rgba(100, 116, 139, 0.15); color: #94A3B8; border-color: rgba(100, 116, 139, 0.3); }}
        .badge.intense {{ background: rgba(37, 99, 235, 0.15); color: #2563EB; border-color: rgba(37, 99, 235, 0.3); }}
        .badge.enabled {{ background: rgba(34, 197, 94, 0.15); color: #4ADE80; border-color: rgba(34, 197, 94, 0.3); }}
        .badge.disabled {{ background: rgba(100, 116, 139, 0.15); color: #94A3B8; border-color: rgba(100, 116, 139, 0.3); }}

        /* Empty State Styles */
        .empty-state {{
            text-align: center;
            padding: 64px 24px;
            background: var(--bg-card);
            border-radius: 12px;
            border: 1px solid var(--border-primary);
        }}

        .empty-icon {{
            width: 80px;
            height: 80px;
            margin: 0 auto 20px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 40px;
            background: var(--accent-muted);
            color: var(--accent-primary);
            border: 2px solid var(--accent-border);
        }}

        .empty-state h3 {{
            color: #FFFFFF;
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 8px;
        }}

        .empty-state p {{
            color: #A0A0A0;
            font-size: 0.95rem;
            max-width: 400px;
            margin: 0 auto;
            line-height: 1.5;
        }}

        .table-container {{
            overflow-x: auto;
            border-radius: 12px;
            border: 1px solid var(--border-primary);
            margin-top: 16px;
            transition: border-color 0.3s ease;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-table);
            transition: background-color 0.3s ease;
        }}

        table a,
        .table-container a {{
            color: var(--link-color);
            text-decoration: none;
            font-weight: 500;
        }}

        table a:hover,
        .table-container a:hover {{
            color: var(--link-hover);
            text-decoration: underline;
        }}

        /* Fixed layout for template tables only (4 columns) */
        #vulnerabilities table {{
            table-layout: fixed;
        }}

        #templates th:nth-child(1) {{ width: 25%; }}
        #templates th:nth-child(2) {{ width: 20%; }}
        #templates th:nth-child(3) {{ width: 15%; }}
        #templates th:nth-child(4) {{ width: 40%; }}

        th {{
            background: var(--bg-table-header);
            color: var(--text-primary);
            padding: 16px 14px;
            text-align: left;
            font-weight: 600;
            font-size: 0.875rem;
            letter-spacing: 0.01em;
            border-bottom: 1px solid var(--border-primary);
            transition: background-color 0.3s ease, color 0.3s ease;
        }}

        td {{
            padding: 14px;
            border-bottom: 1px solid var(--border-secondary);
            color: var(--text-primary);
            font-size: 0.875rem;
            transition: background-color 0.3s ease, color 0.3s ease;
        }}

        /* Word wrap for template tables */
        #templates td {{
            word-wrap: break-word;
            overflow-wrap: break-word;
        }}

        /* Handle long status text in certificates table */
        #certificatesTable td:nth-child(8) {{
            max-width: 300px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            position: relative;
        }}

        /* Show native tooltip for truncated text */
        #certificatesTable td[title]:hover {{
            cursor: inherit;
        }}

        /* Expandable Row Styles */
        .expand-cell {{
            text-align: center;
            cursor: pointer;
            width: 40px;
        }}

        .expand-icon {{
            transition: transform 0.3s ease;
            font-size: 12px;
            color: var(--text-secondary);
            display: inline-block;
        }}

        .cert-row.expanded .expand-icon {{
            transform: rotate(90deg);
        }}

        .cert-row:hover {{
            cursor: pointer;
        }}

        .cert-row.expanded {{
            background-color: var(--bg-expanded-row);
            border-bottom: none;
        }}

        .details-row td {{
            background-color: var(--details-row-bg);
            border-top: none;
            padding: 0;
        }}

        .details-content {{
            padding: 24px;
            border-top: 1px solid var(--border-primary);
            border-bottom: 1px solid var(--border-primary);
            background: var(--details-content-bg); /* ensure expanded rows match current theme tone */
        }}

        .details-grid {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 24px;
        }}

        .detail-item {{
            display: flex;
            flex-direction: column;
            gap: 4px;
        }}

        .detail-label {{
            color: var(--text-tertiary);
            font-size: 0.7rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        .detail-value {{
            color: var(--text-primary);
            font-size: 0.9rem;
            word-break: break-all;
            font-family: monospace;
        }}

        tr:hover td {{
            background: var(--bg-hover);
        }}

        .tab-content {{
            display: none;
        }}

        .tab-content.active {{
            display: block;
        }}

        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-top: 20px;
        }}

        .info-item {{
            padding: 12px;
            background: var(--bg-inner-card);
            border-radius: 8px;
            border: 1px solid var(--border-secondary);
            transition: background-color 0.3s ease, border-color 0.3s ease;
        }}

        .info-label {{
            color: var(--text-tertiary);
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 4px;
        }}

        .info-value {{
            color: var(--text-primary);
            font-size: 0.95rem;
            font-weight: 500;
        }}

        .ca-list {{
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
        }}

        .ca-pill {{
            padding: 4px 10px;
            border-radius: 999px;
            border: 1px solid var(--border-primary);
            background: var(--bg-inner-card);
            color: var(--text-secondary);
            font-size: 0.85rem;
            font-weight: 500;
            white-space: nowrap;
        }}

        /* Pagination Styles - Style 3D: Square Minimal with Pill Indicator */
        .pagination-container {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 24px;
            padding: 20px 0;
            border-top: 1px solid rgba(255, 255, 255, 0.05);
        }}

        .pagination-controls {{
            display: flex;
            gap: 18px;
            align-items: center;
        }}

        .pagination-btn {{
            width: 36px;
            height: 36px;
            background: transparent;
            color: var(--text-secondary);
            border: 1px solid var(--border-primary);
            border-radius: 6px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
            padding: 0;
        }}

        .pagination-btn:hover:not(:disabled) {{
            background: var(--accent-muted);
            border-color: var(--accent-primary);
            color: var(--accent-primary);
        }}

        .pagination-btn:disabled {{
            opacity: 0.2;
            cursor: not-allowed;
        }}

        .pagination-btn svg {{
            width: 18px;
            height: 18px;
        }}

        .pagination-info {{
            color: var(--text-secondary);
            font-size: 14px;
            font-weight: 400;
        }}

        .page-dots {{
            display: flex;
            gap: 6px;
            align-items: center;
        }}

        .page-dot {{
            width: 5px;
            height: 5px;
            border-radius: 2px;
            background: var(--text-secondary);
            opacity: 0.3;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }}

        .page-dot.active {{
            background: #60A5FA;
            opacity: 1;
            width: 20px;
            height: 5px;
        }}

        /* Export Buttons */
        .btn {{
            padding: 8px 16px;
            background: var(--bg-card);
            color: var(--text-primary);
            border: 1px solid var(--border-primary);
            border-radius: 6px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 500;
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
        }}

        :root[data-theme=""white""] .btn {{
            background: #FFFFFF;
        }}

        .btn:hover {{
            background: var(--bg-hover);
            border-color: var(--border-hover);
            color: var(--text-white);
        }}

        /* Dropdown Styles */
        .dropdown {{
            position: relative;
            display: inline-block;
        }}

        .dropdown-menu {{
            display: none;
            position: absolute;
            right: 0;
            background-color: var(--bg-card);
            min-width: 160px;
            box-shadow: none;
            z-index: 100;
            border: 1px solid var(--border-primary);
            border-radius: 6px;
            padding: 4px 0;
            margin-top: 4px;
        }}

        .dropdown-menu.show {{
            display: block;
        }}

        .dropdown-item {{
            color: var(--text-primary);
            padding: 8px 16px;
            text-decoration: none;
            display: flex;
            align-items: center;
            cursor: pointer;
            font-size: 0.85rem;
            transition: background-color 0.2s;
        }}

        .dropdown-item:hover {{
            background-color: var(--bg-hover);
        }}
        
        .dropdown-item.active {{
            background-color: var(--accent-muted);
            color: var(--accent-primary);
        }}

        .dropdown-item .badge {{
            margin-right: 8px;
            font-size: 0.7rem;
            padding: 2px 6px;
        }}

        .dropdown-item[data-source=""INTENSE""] {{
            color: #2563EB;
        }}
    </style>
</head>
<body>
    <div class=""app-container"" id=""appContainer"">
        <!-- Sidebar Navigation -->
        <nav class=""sidebar"" id=""sidebar"">
            <div class=""sidebar-header"">
                <h1>Stelark</h1>
                <div class=""subtitle"">The Ark that hunts the stars</div>
            </div>

            <div class=""nav-section"">
                <div class=""nav-section-title"">Assessment Results</div>
                <a class=""nav-item active"" onclick=""showTab('overview')"">
                    <span class=""nav-icon"">{svgOverview}</span>
                    <span>Overview</span>
                </a>
                {navItemsHtml}
            </div>
        </nav>

        <!-- Main Content -->
        <main class=""main-content"" id=""mainContent"">
            <div class=""top-bar"">
                <button class=""toggle-sidebar-btn"" onclick=""toggleSidebar()"" title=""Toggle Sidebar"">
                    {svgMenu}
                </button>
                <div class=""search-bar"">
                    <input type=""text"" class=""search-input"" id=""searchInput"" placeholder=""Search certificates or templates..."">
                </div>
                <div class=""theme-toggle"" onclick=""toggleTheme()"" id=""themeToggle"">{svgMoon}</div>
            </div>

            <!-- Overview Tab -->
            <div id=""overview"" class=""tab-content active"">
                <div class=""content-header"">
                    <h2>Active Directory Certificate Services Assessment</h2>
                    <p>Comprehensive security analysis for {primaryCAName}</p>
                </div>

                <div class=""stats-grid"">
                    {statsHtml}
                </div>

                <div class=""card"">
                    <div class=""card-header"">
                        <h3 class=""card-title"">Scan Summary</h3>
                    </div>
                    <div class=""info-grid"">
                        <div class=""info-item"">
                            <div class=""info-label"">Scan Type</div>
                            <div class=""info-value"">{scanType}</div>
                        </div>
                        <div class=""info-item"">
                            <div class=""info-label"">CA Name</div>
                            <div class=""info-value"">{primaryCAName}</div>
                        </div>
{multiCaFieldHtml}
                        <div class=""info-item"">
                            <div class=""info-label"">Generated At</div>
                            <div class=""info-value"">{timestamp}</div>
                        </div>
                    </div>
                </div>

                <div class=""card"">
                    <div class=""card-header"">
                        <h3 class=""card-title"">Vulnerability Breakdown</h3>
                    </div>
                    {(vulnerabilityStats.Values.Sum() > 0 ? $@"<div class=""table-container"">
                        <table>
                            <thead>
                                <tr>
                                    <th>Category</th>
                                    <th>Vulnerability Type</th>
                                    <th>Count</th>
                                </tr>
                            </thead>
                            <tbody>
{breakdownRowsHtml}
                            </tbody>
                        </table>
                    </div>" : $@"<div class=""empty-state"">
                        <div class=""empty-icon"">✓</div>
                        <h3>No Vulnerabilities Found</h3>
                        <p>No vulnerable templates, CA permissions, or endpoints were detected in this environment.</p>
                    </div>")}
                </div>
            </div>

            {tabsContentHtml}
        </main>
    </div>

    <script>
        function toggleDropdown(id) {{
            const dropdown = document.getElementById(id);
            const allDropdowns = document.getElementsByClassName('dropdown-menu');
            
            // Close all other dropdowns
            for (let i = 0; i < allDropdowns.length; i++) {{
                if (allDropdowns[i].id !== id) {{
                    allDropdowns[i].classList.remove('show');
                }}
            }}
            
            dropdown.classList.toggle('show');
        }}

        // Close dropdowns when clicking outside
        window.onclick = function(event) {{
            if (!event.target.matches('.dropdown-toggle') && !event.target.closest('.dropdown-toggle')) {{
                const dropdowns = document.getElementsByClassName('dropdown-menu');
                for (let i = 0; i < dropdowns.length; i++) {{
                    const openDropdown = dropdowns[i];
                    if (openDropdown.classList.contains('show')) {{
                        openDropdown.classList.remove('show');
                    }}
                }}
            }}
        }}

        let currentFilter = 'all';

        function filterByESC(escType) {{
            currentFilter = escType;
            
            // Update active state in dropdown
            const dropdownItems = document.querySelectorAll('#filterDropdown .dropdown-item');
            dropdownItems.forEach(item => {{
                item.classList.remove('active');
                if (escType === 'all' && item.textContent === 'All') {{
                    item.classList.add('active');
                }} else if (item.textContent.includes(escType) && escType !== 'all') {{
                    item.classList.add('active');
                }}
            }});

            const table = document.getElementById('certificatesTable');
            const rows = table.querySelectorAll('.cert-row');
            
            rows.forEach(row => {{
                const certData = JSON.parse(row.getAttribute('data-cert-data'));
                const source = certData.Source || '';
                const detailsRow = row.nextElementSibling;
                
                // Check if row matches search term (if any)
                const isSearchHidden = row.hasAttribute('data-search-hidden');
                
                if (escType === 'all' || source === escType) {{
                    row.setAttribute('data-filter-match', 'true');
                    if (!isSearchHidden) {{
                        row.style.display = '';
                    }}
                }} else {{
                    row.setAttribute('data-filter-match', 'false');
                    row.style.display = 'none';
                    if (detailsRow && detailsRow.classList.contains('details-row')) {{
                        detailsRow.style.display = 'none';
                    }}
                    row.classList.remove('expanded');
                }}
            }});
            
            // Update pagination to reflect filtered rows
            if (certPagination) {{
                certPagination.currentPage = 1;
                certPagination.showPage(1);
            }}
        }}

        function sortTable(key, header) {{
            const table = document.getElementById('certificatesTable');
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('.cert-row'));
            
            // Determine sort direction
            let dir = 'asc';
            const currentDir = header.getAttribute('data-sort-dir');
            if (currentDir === 'asc') {{
                dir = 'desc';
            }}
            
            // Reset all headers
            document.querySelectorAll('.sortable-header').forEach(th => {{
                th.removeAttribute('data-sort-dir');
            }});
            
            // Set direction on clicked header
            header.setAttribute('data-sort-dir', dir);
            
            // Create pairs of main row and details row
            const pairs = rows.map(row => {{
                return {{ main: row, detail: row.nextElementSibling }};
            }});
            
            // Sort pairs
            pairs.sort((a, b) => {{
                const aData = JSON.parse(a.main.getAttribute('data-cert-data'));
                const bData = JSON.parse(b.main.getAttribute('data-cert-data'));
                
                let aVal = aData[key] || '';
                let bVal = bData[key] || '';
                
                // Handle special cases
                if (key === 'RequestID' || key === 'Serial') {{
                    // Parse numbers if possible, otherwise string compare
                    const aNum = parseInt(aVal);
                    const bNum = parseInt(bVal);
                    if (!isNaN(aNum) && !isNaN(bNum)) {{
                        return dir === 'asc' ? aNum - bNum : bNum - aNum;
                    }}
                }}
                
                aVal = aVal.toString().toLowerCase();
                bVal = bVal.toString().toLowerCase();
                
                if (dir === 'asc') {{
                    return aVal.localeCompare(bVal);
                }} else {{
                    return bVal.localeCompare(aVal);
                }}
            }});
            
            // Reorder in DOM
            pairs.forEach(pair => {{
                tbody.appendChild(pair.main);
                if (pair.detail) tbody.appendChild(pair.detail);
            }});
            
            // Update pagination
            if (certPagination) {{
                certPagination.refreshRows();
            }}
        }}

        function toggleDetails(row) {{
            // Toggle class on the clicked row
            row.classList.toggle('expanded');
            
            // Find the next row which is the details row
            const nextRow = row.nextElementSibling;
            if (nextRow && nextRow.classList.contains('details-row')) {{
                if (row.classList.contains('expanded')) {{
                    nextRow.style.display = 'table-row';
                }} else {{
                    nextRow.style.display = 'none';
                }}
            }}
        }}

        class Pagination {{
            constructor(tableId, itemsPerPage = 10) {{
                this.tableId = tableId;
                this.itemsPerPage = itemsPerPage;
                this.currentPage = 1;
                this.rows = document.querySelectorAll('#' + tableId + ' .cert-row');
                this.totalPages = Math.ceil(this.rows.length / this.itemsPerPage);

                this.init();
            }}

            init() {{
                this.renderPagination();
                this.showPage(1);
            }}

            showPage(page) {{
                const visibleRows = this.getVisibleRows();
                const visibleTotalPages = Math.ceil(visibleRows.length / this.itemsPerPage);
                
                if (page < 1) page = 1;
                if (page > visibleTotalPages) page = visibleTotalPages;

                this.currentPage = page;

                this.rows.forEach(row => {{
                    if (!row.hasAttribute('data-search-hidden')) {{
                        row.style.display = 'none';
                        // Ensure details row is hidden and expanded state is reset
                        row.classList.remove('expanded');
                        const nextRow = row.nextElementSibling;
                        if (nextRow && nextRow.classList.contains('details-row')) {{
                            nextRow.style.display = 'none';
                        }}
                    }}
                }});

                const start = (page - 1) * this.itemsPerPage;
                const end = start + this.itemsPerPage;

                for (let i = start; i < end && i < visibleRows.length; i++) {{
                    visibleRows[i].style.display = '';
                }}

                this.renderPagination();
            }}
            
            getVisibleRows() {{
                return Array.from(this.rows).filter(row => {{
                    return !row.hasAttribute('data-search-hidden') && 
                           row.getAttribute('data-filter-match') !== 'false';
                }});
            }}

            refreshRows() {{
                this.rows = document.querySelectorAll('#' + this.tableId + ' .cert-row');
                // Stay on current page but validate it
                const visibleRows = this.getVisibleRows();
                const visibleTotalPages = Math.ceil(visibleRows.length / this.itemsPerPage);
                if (this.currentPage > visibleTotalPages && visibleTotalPages > 0) {{
                    this.currentPage = visibleTotalPages;
                }}
                this.showPage(this.currentPage);
            }}

            renderPagination() {{
                const container = document.getElementById('certPagination');
                if (!container) return;

                container.innerHTML = '';

                const visibleRows = this.getVisibleRows();
                const visibleCount = visibleRows.length;
                const visibleTotalPages = Math.ceil(visibleCount / this.itemsPerPage);

                const info = document.createElement('div');
                info.className = 'pagination-info';
                if (visibleCount > 0) {{
                const start = (this.currentPage - 1) * this.itemsPerPage + 1;
                    const end = Math.min(this.currentPage * this.itemsPerPage, visibleCount);
                    info.textContent = 'Showing ' + start + '-' + end + ' of ' + visibleCount;
                }} else {{
                    info.textContent = 'No results';
                }}
                container.appendChild(info);

                const controls = document.createElement('div');
                controls.className = 'pagination-controls';

                const prevBtn = document.createElement('button');
                prevBtn.className = 'pagination-btn';
                prevBtn.disabled = this.currentPage === 1;
                prevBtn.onclick = () => this.showPage(this.currentPage - 1);
                const prevSvg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
                prevSvg.setAttribute('viewBox', '0 0 24 24');
                prevSvg.setAttribute('fill', 'none');
                prevSvg.setAttribute('stroke', 'currentColor');
                prevSvg.setAttribute('stroke-width', '2');
                const prevPath = document.createElementNS('http://www.w3.org/2000/svg', 'path');
                prevPath.setAttribute('d', 'M15 18l-6-6 6-6');
                prevSvg.appendChild(prevPath);
                prevBtn.appendChild(prevSvg);
                controls.appendChild(prevBtn);

                const dotsContainer = document.createElement('div');
                dotsContainer.className = 'page-dots';
                
                const maxDots = 5;
                const dotsToShow = Math.min(maxDots, visibleTotalPages);
                
                let activeDotIndex = 0;
                if (visibleTotalPages <= maxDots) {{
                    activeDotIndex = this.currentPage - 1;
                }} else {{
                    activeDotIndex = Math.floor((this.currentPage - 1) / (visibleTotalPages / dotsToShow));
                    activeDotIndex = Math.min(activeDotIndex, dotsToShow - 1);
                }}
                
                for (let i = 0; i < dotsToShow; i++) {{
                    const dot = document.createElement('div');
                    dot.className = 'page-dot' + (i === activeDotIndex ? ' active' : '');
                    dotsContainer.appendChild(dot);
                }}
                
                controls.appendChild(dotsContainer);

                const nextBtn = document.createElement('button');
                nextBtn.className = 'pagination-btn';
                nextBtn.disabled = this.currentPage === visibleTotalPages || visibleTotalPages === 0;
                nextBtn.onclick = () => this.showPage(this.currentPage + 1);
                const nextSvg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
                nextSvg.setAttribute('viewBox', '0 0 24 24');
                nextSvg.setAttribute('fill', 'none');
                nextSvg.setAttribute('stroke', 'currentColor');
                nextSvg.setAttribute('stroke-width', '2');
                const nextPath = document.createElementNS('http://www.w3.org/2000/svg', 'path');
                nextPath.setAttribute('d', 'M9 18l6-6-6-6');
                nextSvg.appendChild(nextPath);
                nextBtn.appendChild(nextSvg);
                controls.appendChild(nextBtn);

                container.appendChild(controls);
            }}

            render() {{
                this.renderPagination();
            }}
        }}

        // Initialize pagination
        let certPagination;
        document.addEventListener('DOMContentLoaded', function() {{
            // Only initialize pagination if certificates table exists
            const certTable = document.getElementById('certificatesTable');
            if (certTable) {{
            certPagination = new Pagination('certificatesTable', 10);
            }}
        }});

        function showTab(tabName) {{
            document.querySelectorAll('.tab-content').forEach(tab => {{
                tab.classList.remove('active');
            }});

            document.querySelectorAll('.nav-item').forEach(item => {{
                item.classList.remove('active');
            }});

            const tabElement = document.getElementById(tabName);
            if (tabElement) {{
                tabElement.classList.add('active');
            }}

            if (event && event.currentTarget) {{
            event.currentTarget.classList.add('active');
            }}
        }}

        function toggleSidebar() {{
            document.getElementById('sidebar').classList.toggle('collapsed');
            document.getElementById('mainContent').classList.toggle('expanded');
        }}

        function toggleTheme() {{
            const html = document.documentElement;
            const themeToggle = document.getElementById('themeToggle');
            const currentTheme = html.getAttribute('data-theme');
            const svgMoon = '{svgMoon}';
            const svgSun = '{svgSun}';
            const themeOrder = ['nebula', 'white'];
            const iconMap = {{
                nebula: svgMoon,
                white: svgSun
            }};

            const currentIndex = themeOrder.indexOf(currentTheme);
            const nextTheme = themeOrder[(currentIndex + 1) % themeOrder.length];
            html.setAttribute('data-theme', nextTheme);
            themeToggle.innerHTML = iconMap[nextTheme];
            localStorage.setItem('theme', nextTheme);
        }}

        (function initTheme() {{
            const savedTheme = localStorage.getItem('theme');
            const html = document.documentElement;
            const themeToggle = document.getElementById('themeToggle');
            const svgMoon = '{svgMoon}';
            const svgSun = '{svgSun}';
            const themeOrder = ['nebula', 'white'];
            const iconMap = {{
                nebula: svgMoon,
                white: svgSun
            }};
            const legacyMap = {{
                dark: 'nebula',
                light: 'white'
            }};

            const normalizedTheme = themeOrder.includes(savedTheme)
                ? savedTheme
                : (legacyMap[savedTheme] || 'nebula');
            html.setAttribute('data-theme', normalizedTheme);
            themeToggle.innerHTML = iconMap[normalizedTheme];
        }})();

        function performSearch(query) {{
            const searchTerm = query.toLowerCase().trim();

            if (!searchTerm) {{
                resetSearch();
                return;
            }}

            const certRows = document.querySelectorAll('#certificatesTable .cert-row');
            let visibleCertCount = 0;

            certRows.forEach(row => {{
                const text = row.textContent.toLowerCase();
                
                // Include details in search
                const nextRow = row.nextElementSibling;
                let detailsText = '';
                if (nextRow && nextRow.classList.contains('details-row')) {{
                    detailsText = nextRow.textContent.toLowerCase();
                }}

                if (text.includes(searchTerm) || detailsText.includes(searchTerm)) {{
                    row.removeAttribute('data-search-hidden');
                }} else {{
                    row.setAttribute('data-search-hidden', 'true');
                    row.style.display = 'none';
                    
                    // Hide details if parent is hidden
                    if (nextRow && nextRow.classList.contains('details-row')) {{
                        nextRow.style.display = 'none';
                    }}
                    row.classList.remove('expanded');
                }}
            }});
            const allTables = document.querySelectorAll('#vulnerabilities table tbody');
            allTables.forEach(tbody => {{
                const rows = tbody.querySelectorAll('tr');
                let visibleInTable = false;

                rows.forEach(row => {{
                    const text = row.textContent.toLowerCase();
                    if (text.includes(searchTerm)) {{
                        row.style.display = '';
                        visibleInTable = true;
                    }} else {{
                        row.style.display = 'none';
                    }}
                }});

                const card = tbody.closest('.card');
                if (card && !visibleInTable) {{
                    card.style.display = 'none';
                }} else if (card) {{
                    card.style.display = '';
                }}
            }});

            if (certPagination) {{
                certPagination.rows = document.querySelectorAll('#certificatesTable .cert-row');
                certPagination.currentPage = 1;
                certPagination.showPage(1);
            }}
        }}

        function resetSearch() {{
            const certRows = document.querySelectorAll('#certificatesTable .cert-row');
            certRows.forEach(row => {{
                row.removeAttribute('data-search-hidden');
            }});

            const allTables = document.querySelectorAll('#vulnerabilities table tbody');
            allTables.forEach(tbody => {{
                const rows = tbody.querySelectorAll('tr');
                rows.forEach(row => {{
                    row.style.display = '';
                }});
            }});

            const allCards = document.querySelectorAll('#templates .card');
            allCards.forEach(card => {{
                card.style.display = '';
            }});

            if (certPagination) {{
                certPagination.rows = document.querySelectorAll('#certificatesTable .cert-row');
                certPagination.currentPage = 1;
                certPagination.showPage(1);
            }}
        }}

        document.addEventListener('DOMContentLoaded', function() {{
            const searchInput = document.getElementById('searchInput');
            if (searchInput) {{
                searchInput.addEventListener('input', function(e) {{
                    performSearch(e.target.value);
                }});

                searchInput.addEventListener('keydown', function(e) {{
                    if (e.key === 'Escape') {{
                        searchInput.value = '';
                        resetSearch();
                    }}
                }});
            }}
        }});

        function exportCertificates(format) {{
            const table = document.getElementById('certificatesTable');
            const rows = table.querySelectorAll('.cert-row');
            const certificates = [];

            rows.forEach(row => {{
                const certDataAttr = row.getAttribute('data-cert-data');
                if (certDataAttr) {{
                    try {{
                        const unescaped = certDataAttr.replace(/&quot;/g, '""').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>');
                        const cert = JSON.parse(unescaped);
                        certificates.push(sanitizeCertificate(cert));
                    }} catch (e) {{
                        console.error('Failed to parse certificate data:', e, certDataAttr);
                        const cells = row.cells;
                        certificates.push(sanitizeCertificate({{
                            Source: cells[0].textContent.trim(),
                            RequestID: cells[1].textContent.trim(),
                            Requester: cells[2].textContent.trim(),
                            SANUPN: cells[3].textContent.trim(),
                            Template: cells[4].textContent.trim(),
                            SerialNumber: cells[5].textContent.trim(),
                            SubmissionDate: cells[6].textContent.trim(),
                            NotBefore: cells[7].textContent.trim(),
                            NotAfter: cells[8].textContent.trim(),
                            Status: cells[9].textContent.trim()
                        }}));
                    }}
                }} else {{
                    const cells = row.cells;
                    certificates.push(sanitizeCertificate({{
                        Source: cells[0].textContent.trim(),
                        RequestID: cells[1].textContent.trim(),
                        Requester: cells[2].textContent.trim(),
                        SANUPN: cells[3].textContent.trim(),
                        Template: cells[4].textContent.trim(),
                        SerialNumber: cells[5].textContent.trim(),
                        SubmissionDate: cells[6].textContent.trim(),
                        NotBefore: cells[7].textContent.trim(),
                        NotAfter: cells[8].textContent.trim(),
                        Status: cells[9].textContent.trim()
                    }}));
                }}
            }});

            if (format === 'csv') {{
                exportAsCSV(certificates);
            }} else if (format === 'json') {{
                exportAsJSON(certificates);
            }}
        }}

        function sanitizeCertificate(cert) {{
            if (!cert || typeof cert !== 'object') {{
                return {{}};
            }}

            const sanitized = {{ ...cert }};
            delete sanitized.ContainsSAN;
            delete sanitized.IsSuspicious;
            return sanitized;
        }}

        function exportAsCSV(data) {{
            function csvEscape(val) {{
                if (val === null || val === undefined) return '""';
                const s = String(val);
                return '""' + s.replace(/""/g, '""""') + '""';
            }}
            
            const headers = ['Source', 'Request ID', 'Requester', 'Principal', 'Template Name', 'Template', 'SAN/UPN', 'Serial Number', 'Certificate Hash', 'Template OID', 'Submission Date', 'Not Before', 'Not After', 'Status', 'EKUs', 'Machine', 'Process'];
            const rows = [];
            
            rows.push(headers.map(csvEscape).join(','));
            
            for (let i = 0; i < data.length; i++) {{
                const cert = data[i];
                const serial = cert.Serial || cert.SerialNumber || '';
                const certHash = cert.CertHash || cert.CertificateHash || '';
                const status = cert.DispositionMsg || cert.Status || '';
                const ekus = Array.isArray(cert.EKUs) ? cert.EKUs.join('; ') : (cert.EKUs || '');
                
                const row = [
                    csvEscape(cert.Source || ''),
                    csvEscape(cert.RequestID || ''),
                    csvEscape(cert.Requester || ''),
                    csvEscape(cert.Principal || ''),
                    csvEscape(cert.TemplateName || ''),
                    csvEscape(cert.Template || ''),
                    csvEscape(cert.SANUPN || ''),
                    csvEscape(serial),
                    csvEscape(certHash),
                    csvEscape(cert.TemplateOID || ''),
                    csvEscape(cert.SubmissionDate || ''),
                    csvEscape(cert.NotBefore || ''),
                    csvEscape(cert.NotAfter || ''),
                    csvEscape(status),
                    csvEscape(ekus),
                    csvEscape(cert.Machine || ''),
                    csvEscape(cert.Process || '')
                ];
                rows.push(row.join(','));
            }}
            
            // Join with CRLF - use actual newline characters, not escape sequences
            // In JavaScript, String.fromCharCode(13, 10) creates actual CRLF
            const crlf = String.fromCharCode(13, 10);
            const csvContent = rows.join(crlf);
            downloadFile(csvContent, 'Stelark Certificates.csv', 'text/csv;charset=utf-8');
        }}

        function exportAsJSON(data) {{
            const json = JSON.stringify(data, null, 2);
            downloadFile(json, 'Stelark Certificates.json', 'application/json');
        }}

        function downloadFile(content, filename, contentType) {{
            // For CSV files, add UTF-8 BOM for Excel compatibility
            let finalContent = content;
            if (contentType.includes('csv')) {{
                const BOM = String.fromCharCode(0xFEFF);
                finalContent = BOM + content;
            }}
            
            // Create blob - don't use 'native' endings, preserve CRLF as-is
            const blob = new Blob([finalContent], {{ 
                type: contentType
            }});
            
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        }}
    </script>
</body>
</html>";
        }

        private string GenerateCAVulnerabilitiesContent()
        {
            if (!_state.FoundCAServers)
            {
                return "";
            }

            var content = new System.Text.StringBuilder();

            // ESC6 CAs
            if (_state.ESC6VulnCAs.Count > 0)
            {
                var esc6Rows = new System.Text.StringBuilder();
                foreach (var ca in _state.ESC6VulnCAs)
                {
                    esc6Rows.AppendLine($@"
                                <tr>
                                    <td>{System.Security.SecurityElement.Escape(ca.Server ?? "")}</td>
                                    <td>{System.Security.SecurityElement.Escape(ca.EditFlags ?? "")}</td>
                                    <td>{(ca.HasEditfAttributeSubjectAltName2 ? "Yes" : "No")}</td>
                                    <td>{System.Security.SecurityElement.Escape(ca.Description ?? "")}</td>
                                </tr>");
                }

                content.AppendLine($@"
                <div class=""card"">
                    <div class=""card-header"">
                        <h3 class=""card-title""><span class=""badge esc6"" style=""margin-right: 12px; font-size: 0.8rem; border-width: 1px;"">ESC6</span>Vulnerable CAs ({_state.ESC6VulnCAs.Count})</h3>
                    </div>
                    <p style=""color: #A0A0A0; margin-bottom: 16px;"">Certificate Authorities with EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled, allowing requesters to specify Subject Alternative Names in certificate requests.</p>
                    <div class=""table-container"">
                        <table>
                            <thead>
                                <tr>
                                    <th>CA Server</th>
                                    <th>Edit Flags</th>
                                    <th>Has Vulnerable Flag</th>
                                    <th>Description</th>
                                </tr>
                            </thead>
                            <tbody>
                                {esc6Rows}
                            </tbody>
                        </table>
                    </div>
                </div>");
            }
            else
            {
                content.AppendLine($@"
                <div class=""card"">
                    <div class=""card-header"">
                        <h3 class=""card-title""><span class=""badge esc6"" style=""margin-right: 12px; font-size: 0.8rem; border-width: 1px;"">ESC6</span>Vulnerable CAs (0)</h3>
                </div>
                    <p style=""color: #A0A0A0; margin-bottom: 16px;"">Certificate Authorities with EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled, allowing requesters to specify Subject Alternative Names in certificate requests.</p>
                    <div class=""empty-state"">
                        <div class=""empty-icon"">✓</div>
                        <h3>No ESC6 Vulnerabilities Found</h3>
                        <p>No Certificate Authorities with the vulnerable EDITF_ATTRIBUTESUBJECTALTNAME2 flag were detected. This is a positive security finding.</p>
            </div>
                </div>");
            }

            // ESC7 Permissions
            if (_state.ESC7VulnCAPermissions.Count > 0)
            {
                var esc7Rows = new System.Text.StringBuilder();
                foreach (var perm in _state.ESC7VulnCAPermissions)
                {
                    esc7Rows.AppendLine($@"
                                <tr>
                                    <td>{System.Security.SecurityElement.Escape(perm.Server ?? "")}</td>
                                    <td>{System.Security.SecurityElement.Escape(perm.Principal ?? "")}</td>
                                    <td>{System.Security.SecurityElement.Escape(perm.Permission ?? "")}</td>
                                    <td>{(perm.IsPrivilegedAccount ? "Yes" : "No")}</td>
                                    <td>{System.Security.SecurityElement.Escape(perm.Description ?? "")}</td>
                                </tr>");
                }

                content.AppendLine($@"
                <div class=""card"">
                    <div class=""card-header"">
                        <h3 class=""card-title""><span class=""badge esc7"" style=""margin-right: 12px; font-size: 0.8rem; border-width: 1px;"">ESC7</span>Dangerous CA Permissions ({_state.ESC7VulnCAPermissions.Count})</h3>
                    </div>
                    <p style=""color: #A0A0A0; margin-bottom: 16px;"">Overprivileged accounts with dangerous CA permissions that can manage CA configuration or certificates.</p>
                    <div class=""table-container"">
                        <table>
                            <thead>
                                <tr>
                                    <th>CA Server</th>
                                    <th>Principal</th>
                                    <th>Permission</th>
                                    <th>Privileged Account</th>
                                    <th>Description</th>
                                </tr>
                            </thead>
                            <tbody>
                                {esc7Rows}
                            </tbody>
                        </table>
                    </div>
                </div>");
            }
            else
            {
                content.AppendLine($@"
                <div class=""card"">
                    <div class=""card-header"">
                        <h3 class=""card-title""><span class=""badge esc7"" style=""margin-right: 12px; font-size: 0.8rem; border-width: 1px;"">ESC7</span>Dangerous CA Permissions (0)</h3>
                    </div>
                    <p style=""color: #A0A0A0; margin-bottom: 16px;"">Overprivileged accounts with dangerous CA permissions that can manage CA configuration or certificates.</p>
                    <div class=""empty-state"">
                        <div class=""empty-icon"">✓</div>
                        <h3>No ESC7 Vulnerabilities Found</h3>
                        <p>No dangerous CA permissions granted to low-privileged accounts were detected. This is a positive security finding.</p>
                    </div>
                </div>");
            }

            // ESC8 Endpoints
            if (_state.ESC8VulnEndpoints.Count > 0)
            {
                var esc8Rows = new System.Text.StringBuilder();
                foreach (var endpoint in _state.ESC8VulnEndpoints)
                {
                    esc8Rows.AppendLine($@"
                                <tr>
                                    <td>{System.Security.SecurityElement.Escape(endpoint.Server ?? "")}</td>
                                    <td><a href=""{System.Security.SecurityElement.Escape(endpoint.URL ?? "")}"" target=""_blank"">{System.Security.SecurityElement.Escape(endpoint.URL ?? "")}</a></td>
                                </tr>");
                }

                content.AppendLine($@"
                <div class=""card"">
                    <div class=""card-header"">
                        <h3 class=""card-title""><span class=""badge esc8"" style=""margin-right: 12px; font-size: 0.8rem; border-width: 1px;"">ESC8</span>Vulnerable Web Endpoints ({_state.ESC8VulnEndpoints.Count})</h3>
                    </div>
                    <p style=""color: #A0A0A0; margin-bottom: 16px;"">AD CSweb enrollment endpoints that can be exploited via NTLM relay attacks.</p>
                    <div class=""table-container"">
                        <table>
                            <thead>
                                <tr>
                                    <th>Server</th>
                                    <th>URL</th>
                                </tr>
                            </thead>
                            <tbody>
                                {esc8Rows}
                            </tbody>
                        </table>
                    </div>
                </div>");
            }
            else
            {
                content.AppendLine($@"
                <div class=""card"">
                    <div class=""card-header"">
                        <h3 class=""card-title""><span class=""badge esc8"" style=""margin-right: 12px; font-size: 0.8rem; border-width: 1px;"">ESC8</span>Vulnerable Web Endpoints (0)</h3>
                    </div>
                    <p style=""color: #A0A0A0; margin-bottom: 16px;"">AD CSweb enrollment endpoints that can be exploited via NTLM relay attacks.</p>
                    <div class=""empty-state"">
                        <div class=""empty-icon"">✓</div>
                        <h3>No ESC8 Vulnerabilities Found</h3>
                        <p>No vulnerable web enrollment endpoints were detected. This is a positive security finding.</p>
                    </div>
                </div>");
            }

            return content.ToString();
        }

        private string GenerateFullReportContent()
        {
            // Check if no CA infrastructure exists first
            if (!_state.FoundCAServers)
            {
                return GenerateNoDataSection();
            }

            var content = @"";

            // ESC1 Templates
            if (_state.ESC1VulnTemplates.Count > 0)
            {
                content += $@"
        <div class=""section"">
            <h2>ESC1 Vulnerable Templates ({_state.ESC1VulnTemplates.Count})</h2>
            <div class=""summary-info"">
                <strong>Risk:</strong> These templates allow Subject Alternative Name (SAN) spoofing, enabling privilege escalation attacks.
            </div>
            <div class=""filters"">
                <input type=""text"" class=""filter-input"" placeholder=""Search ESC1 templates..."" data-table=""esc1Table"">
            </div>
            <div class=""table-container"">
                <table id=""esc1Table"">
                    <thead>
                        <tr>
                            <th>Display Name</th>
                            <th>CN</th>
                            <th>Vulnerable EKU</th>
                            <th>Enabled</th>
                            <th>Enrollment Groups</th>
                        </tr>
                    </thead>
                    <tbody>";

                foreach (var template in _state.ESC1VulnTemplates)
                {
                    content += $@"
                        <tr>
                            <td>{template.DisplayName}</td>
                            <td>{template.CN}</td>
                            <td>{GetTemplateVulnerabilityBadge(template.VulnerabilityReason)}</td>
                            <td>{(template.IsEnabled ? "Yes" : "No")}</td>
                            <td>{string.Join(", ", template.EnrollmentGroups)}</td>
                        </tr>";
                }

                content += @"
                    </tbody>
                </table>
            </div>
        </div>";
            }

            // ESC2 Templates (similar structure)
            if (_state.ESC2VulnTemplates.Count > 0)
            {
                content += GenerateTemplateSection("ESC2", _state.ESC2VulnTemplates,     
                    "Templates with 'Any Purpose' or 'No EKU' EKU that can be abused for various attacks.");
            }

            // ESC3 Templates
            if (_state.ESC3VulnTemplates.Count > 0)
            {
                content += GenerateTemplateSection("ESC3", _state.ESC3VulnTemplates, 
                    "Templates with Certificate Request Agent EKU for enrollment on behalf of others.");
            }

            // ESC4 Templates
            if (_state.ESC4VulnTemplates.Count > 0)
            {
                content += GenerateTemplateSection("ESC4", _state.ESC4VulnTemplates, 
                    "Templates with vulnerable access control allowing unauthorized certificate enrollment.");
            }

            // ESC6 CAs
            if (_state.ESC6VulnCAs.Count > 0)
            {
                content += $@"
        <div class=""section"">
            <h2>ESC6 Vulnerable CAs ({_state.ESC6VulnCAs.Count})</h2>
            <div class=""summary-info"">
                <strong>Risk:</strong> Certificate Authorities with EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled.
            </div>
            <div class=""table-container"">
                <table>
                    <thead>
                        <tr>
                            <th>CA Server</th>
                            <th>Edit Flags</th>
                            <th>Has Vulnerable Flag</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>";

                foreach (var ca in _state.ESC6VulnCAs)
                {
                    content += $@"
                        <tr>
                            <td>{ca.Server}</td>
                            <td>{ca.EditFlags}</td>
                            <td>{(ca.HasEditfAttributeSubjectAltName2 ? "Yes" : "No")}</td>
                            <td>{ca.Description}</td>
                        </tr>";
                }

                content += @"
                    </tbody>
                </table>
            </div>
        </div>";
            }

            // ESC7 Permissions
            if (_state.ESC7VulnCAPermissions.Count > 0)
            {
                content += $@"
        <div class=""section"">
            <h2>ESC7 Dangerous CA Permissions ({_state.ESC7VulnCAPermissions.Count})</h2>
            <div class=""summary-info"">
                <strong>Risk:</strong> Overprivileged accounts with dangerous CA permissions.
            </div>
            <div class=""table-container"">
                <table>
                    <thead>
                        <tr>
                            <th>CA Server</th>
                            <th>Principal</th>
                            <th>Permission</th>
                            <th>Privileged Account</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>";

                foreach (var perm in _state.ESC7VulnCAPermissions)
                {
                    content += $@"
                        <tr>
                            <td>{perm.Server}</td>
                            <td>{perm.Principal}</td>
                            <td>{perm.Permission}</td>
                            <td>{(perm.IsPrivilegedAccount ? "Yes" : "No")}</td>
                            <td>{perm.Description}</td>
                        </tr>";
                }

                content += @"
                    </tbody>
                </table>
            </div>
        </div>";
            }

            // ESC8 Endpoints
            if (_state.ESC8VulnEndpoints.Count > 0)
            {
                content += $@"
        <div class=""section"">
            <h2>ESC8 Vulnerable Web Endpoints ({_state.ESC8VulnEndpoints.Count})</h2>
            <div class=""summary-info"">
                <strong>Risk:</strong> AD CSweb enrollment endpoints that can be exploited.
            </div>
            <div class=""table-container"">
                <table>
                    <thead>
                        <tr>
                            <th>Server</th>
                            <th>URL</th>
                        </tr>
                    </thead>
                    <tbody>";

                foreach (var endpoint in _state.ESC8VulnEndpoints)
                {
                    content += $@"
                        <tr>
                            <td>{endpoint.Server}</td>
                            <td><a href=""{endpoint.URL}"" target=""_blank"">{endpoint.URL}</a></td>
                        </tr>";
                }

                content += @"
                    </tbody>
                </table>
            </div>
        </div>";
            }

            // Suspicious Certificates - only include certificates marked as suspicious (with SAN)
            var allCerts = new List<Certificate>();
            allCerts.AddRange(_state.ESC1Certificates.Where(c => c.IsSuspicious));
            allCerts.AddRange(_state.ESC2Certificates.Where(c => c.IsSuspicious));
            allCerts.AddRange(_state.ESC3Certificates.Where(c => c.IsSuspicious));
            allCerts.AddRange(_state.ESC4Certificates.Where(c => c.IsSuspicious));
            allCerts.AddRange(_state.IntenseUniqueCertificates);

            if (allCerts.Count > 0)
            {
                content += GenerateCertificatesSection(allCerts, "All Suspicious Certificates");
            }

            return content.Length > 0 ? content : GenerateNoDataSection();
        }

        private string GenerateIntenseReportContent()
        {
            // Check if no CA infrastructure exists first
            if (!_state.FoundCAServers)
            {
                return GenerateNoDataSection();
            }

            if (_state.IntenseUniqueCertificates.Count > 0)
            {
                return GenerateCertificatesSection(_state.IntenseUniqueCertificates, "Intense Scan - Suspicious Certificates");
            }

            return @"
        <div class=""section"">
            <div class=""no-data"">
                <h2>No Suspicious Certificates Found</h2>
                <p>The intense certificate scan completed with no suspicious certificates detected.</p>
            </div>
        </div>";
        }

        private string GenerateTemplateSection(string escType, List<VulnerableTemplate> templates, string description)
        {
            var tableId = $"{escType.ToLower()}Table";
            var columnHeader = escType == "ESC4" ? "Vulnerability Type" : "Vulnerable EKU";
            var isESC4 = escType == "ESC4";
            var lastColumnHeader = isESC4 ? "Risky Groups" : "Enrollment Groups";
            
            var content = $@"
        <div class=""section"">
            <h2>{escType} Vulnerable Templates ({templates.Count})</h2>
            <div class=""summary-info"">
                <strong>Risk:</strong> {description}
            </div>
            <div class=""filters"">
                <input type=""text"" class=""filter-input"" placeholder=""Search {escType} templates..."" data-table=""{tableId}"">
            </div>
            <div class=""table-container"">
                <table id=""{tableId}"">
                    <thead>
                        <tr>
                            <th>Display Name</th>
                            <th>CN</th>
                            <th>{columnHeader}</th>
                            <th>Enabled</th>
                            <th>{lastColumnHeader}</th>
                            {(isESC4 ? "<th>Dangerous Permissions</th>" : "")}
                        </tr>
                    </thead>
                    <tbody>";

            foreach (var template in templates)
            {
                if (isESC4)
                {
                    // ESC4 templates might have multiple risky groups, create separate rows for each
                    if (template.RiskyGroups.Count > 0)
                    {
                        foreach (var riskyGroup in template.RiskyGroups)
                        {
                            content += $@"
                        <tr>
                            <td>{template.DisplayName}</td>
                            <td>{template.CN}</td>
                            <td>{GetTemplateVulnerabilityBadge(template.VulnerabilityReason)}</td>
                            <td>{(template.IsEnabled ? "Yes" : "No")}</td>
                            <td>{riskyGroup.Group}</td>
                            <td>{ConvertPermissionsToFriendlyNames(riskyGroup.Rights)}</td>
                        </tr>";
                        }
                    }
                    else
                    {
                        content += $@"
                        <tr>
                            <td>{template.DisplayName}</td>
                            <td>{template.CN}</td>
                            <td>{GetTemplateVulnerabilityBadge(template.VulnerabilityReason)}</td>
                            <td>{(template.IsEnabled ? "Yes" : "No")}</td>
                            <td>No risky groups found</td>
                            <td>-</td>
                        </tr>";
                    }
                }
                else
                {
                    // Non-ESC4 templates
                    var enrollmentGroups = string.Join(", ", template.EnrollmentGroups);
                    content += $@"
                        <tr>
                            <td>{template.DisplayName}</td>
                            <td>{template.CN}</td>
                            <td>{GetTemplateVulnerabilityBadge(template.VulnerabilityReason)}</td>
                            <td>{(template.IsEnabled ? "Yes" : "No")}</td>
                            <td>{enrollmentGroups}</td>
                        </tr>";
                }
            }

            content += @"
                    </tbody>
                </table>
            </div>
        </div>";

            return content;
        }

        private string GenerateCertificatesSection(List<Certificate> certificates, string title)
        {
            var tableId = "certificatesTable";

            // Check if any certificates have Machine or Process information
            var hasMachineData = certificates.Any(c => !string.IsNullOrEmpty(c.Machine) && c.Machine != "N/A");
            var hasProcessData = certificates.Any(c => !string.IsNullOrEmpty(c.Process) && c.Process != "N/A");

            // Build header row with validation status
            var headerCells = new List<string>
            {
                "<th>Source</th>",
                "<th>Request ID</th>",
                "<th>Requester</th>",
                "<th>SAN/UPN</th>",
                "<th>Template</th>"
            };


            headerCells.AddRange(new[]
            {
                "<th>Serial Number</th>",
                "<th>Submission Date</th>",
                "<th>Status</th>"
            });

            if (hasMachineData) headerCells.Add("<th>Machine</th>");
            if (hasProcessData) headerCells.Add("<th>Process</th>");
            headerCells.Add("<th>Actions</th>");

            // Build expandable data rows with validation results
            var rows = certificates.Select((cert, index) =>
            {
                var certId = $"cert_{cert.RequestID}_{index}";

                var cells = new List<string>
                {
                    $"<td><span class=\"vulnerability-badge {cert.Source.ToLower()}\">{cert.Source}</span></td>",
                    $"<td>{cert.RequestID.NormalizeRequestID()}</td>",
                    $"<td>{cert.Requester}</td>",
                    $"<td>{(cert.ContainsSAN ? cert.SANUPN : "N/A")}</td>",
                    $"<td>{cert.Template}</td>"
                };


                cells.AddRange(new[]
                {
                    $"<td>{cert.Serial}</td>",
                    $"<td>{cert.SubmissionDate}</td>",
                    $"<td>{cert.DispositionMsg}</td>"
                });

                if (hasMachineData) cells.Add($"<td>{cert.Machine}</td>");
                if (hasProcessData) cells.Add($"<td>{cert.Process}</td>");

                cells.Add($"<td><button class=\"btn-expand\" onclick=\"toggleCertDetails('{certId}')\" title=\"View Details\">Details</button></td>");

                var mainRow = $"<tr class=\"certificate-row\">{string.Join("", cells)}</tr>";
                var detailRow = GenerateCertificateDetailRow(cert, certId, headerCells.Count);

                return mainRow + detailRow;
            });

            return $@"
        <div class=""section"">
            <h2>{title} ({certificates.Count})</h2>
            <div class=""filters"">
                <input type=""text"" class=""filter-input"" placeholder=""Search certificates..."" data-table=""{tableId}"">
            </div>
            <div class=""table-container"">
                <table id=""{tableId}"" class=""certificates-table"">
                    <thead>
                        <tr>
                            {string.Join("", headerCells)}
                        </tr>
                    </thead>
                    <tbody>
                        {string.Join("", rows)}
                    </tbody>
                </table>
            </div>
        </div>";
        }



        /// <summary>
        /// Generate certificate detail row for expandable display
        /// </summary>
        private string GenerateCertificateDetailRow(Certificate cert, string certId, int columnSpan)
        {
            return $@"
                <tr id=""{certId}_details"" class=""certificate-details hidden"">
                    <td colspan=""{columnSpan}"">
                        <div class=""detail-panel"">
                            <div class=""forensic-section"">
                                <h4>Certificate Details</h4>
                                <div class=""forensic-grid"">
                                    <div class=""forensic-item"">
                                        <strong>Certificate Hash:</strong> {cert.CertHash}
                                    </div>
                                    <div class=""forensic-item"">
                                        <strong>Template Name:</strong> {(!string.IsNullOrEmpty(cert.Template) ? cert.Template : cert.TemplateName)}
                                    </div>
                                    <div class=""forensic-item"">
                                        <strong>Not Before:</strong> {cert.NotBefore}
                                    </div>
                                    <div class=""forensic-item"">
                                        <strong>Not After:</strong> {cert.NotAfter}
                                    </div>
                                    <div class=""forensic-item"">
                                        <strong>EKUs:</strong> {(cert.EKUs.Any() ? string.Join(", ", cert.EKUs) : "None")}
                                    </div>
                                    <div class=""forensic-item"">
                                        <strong>Principal:</strong> {cert.Principal}
                                    </div>
                                </div>
                            </div>
                        </div>
                    </td>
                </tr>";
        }




        private string GetTemplateVulnerabilityBadge(string vulnerabilityReason)
        {
            return vulnerabilityReason switch
            {
                "Client Authentication" => "<span class=\"eku-badge\">Client Authentication</span>",
                "Any Purpose" => "<span class=\"eku-badge\">Any Purpose</span>",
                "No EKU" => "<span class=\"eku-badge\" style=\"background: #e74c3c;\">No EKU</span>",
                "Certificate Request Agent" => "<span class=\"eku-badge\">Certificate Request Agent</span>", 
                "Access Control" => "<span class=\"eku-badge\">Access Control</span>",
                _ => "<span class=\"eku-badge\">Unknown</span>"
            };
        }

        private string ConvertPermissionsToFriendlyNames(string rawPermissions)
        {
            var permissions = rawPermissions.Split(new[] { ", " }, StringSplitOptions.RemoveEmptyEntries);
            var friendlyPermissions = new List<string>();
            
            foreach (var permission in permissions)
            {
                var friendlyName = permission.Trim() switch
                {
                    "FullControl" => "<span class=\"permission-badge danger\">Full Control</span>",
                    "WriteDacl" => "<span class=\"permission-badge warning\">Modify Permissions</span>",
                    "WriteOwner" => "<span class=\"permission-badge warning\">Take Ownership</span>",
                    "WriteProperty" => "<span class=\"permission-badge info\">Write Properties</span>",
                    "ExtendedRight" => "<span class=\"permission-badge info\">Extended Rights</span>",
                    "GenericWrite" => "<span class=\"permission-badge warning\">Generic Write</span>",
                    "GenericAll" => "<span class=\"permission-badge danger\">Generic All</span>",
                    _ => $"<span class=\"permission-badge\">{permission}</span>"
                };
                friendlyPermissions.Add(friendlyName);
            }
            
            return string.Join(" ", friendlyPermissions);
        }

        private string GenerateNoDataSection()
        {
            // No CA infrastructure detected
            if (!_state.FoundCAServers)
            {
                return @"
        <div class=""section"">
            <div class=""no-data"">
                <h2>No CA Infrastructure Detected</h2>
                <p>No Certificate Authority servers were found in Active Directory.</p>
                <p><strong>Possible causes:</strong></p>
                <ul style=""text-align: left; display: inline-block;"">
                    <li>Limited Active Directory connectivity</li>
                    <li>No AD CS infrastructure deployed in the domain</li>
                    <li>Network or permission issues preventing CA discovery</li>
                </ul>
                <p><strong>Recommendation:</strong> Verify AD connectivity and AD CS deployment</p>
            </div>
        </div>";
            }

            // CA found but not running on CA server
            if (_state.FoundCAServers && !_state.IsLocalCAServer)
            {
                var caList = _state.CAServerHostnames.Count > 0 ? 
                    string.Join(", ", _state.CAServerHostnames) : "the CA server";
                
                return @$"
        <div class=""section"">
            <div class=""no-data"">
                <h2>Limited Analysis Performed</h2>
                <p>Stelark was not run on a Certificate Authority server, so vulnerability analysis could not be performed.</p>
                <p><strong>For complete AD CS security assessment:</strong></p>
                <p>Run Stelark directly on the CA server: <strong>{caList}</strong></p>
            </div>
        </div>";
            }
            
            // Normal case - full analysis with no vulnerabilities
            return @"
        <div class=""section"">
            <div class=""no-data"">
                <h2>No Vulnerabilities Found</h2>
                <p>The scan completed successfully with no AD CS vulnerabilities detected.</p>
            </div>
        </div>";
        }

        private int GetChecksPerformedCount(bool intenseOnly)
        {
            // If not running on CA server, only CA discovery check is performed
            if (_state.FoundCAServers && !_state.IsLocalCAServer)
            {
                return 1; // Only CA discovery
            }
            
            // If no CA servers found, only discovery attempt is made
            if (!_state.FoundCAServers)
            {
                return 1; // Only CA discovery attempt
            }
            
            // Normal CA server execution
            return intenseOnly ? 1 : (_state.IntenseScanRun ? 8 : 7);
        }

        public void ZipOutputs()
        {
            if (string.IsNullOrEmpty(_state.OutputDir) || !Directory.EnumerateFileSystemEntries(_state.OutputDir).Any())
            {
                ConsoleHelper.WriteWarning("No output files found to be zipped.");
                return;
            }

            var parentDir = Directory.GetParent(_state.OutputDir)?.FullName;
            if (parentDir == null)
            {
                ConsoleHelper.WriteError("Could not determine parent directory for zip file creation.");
                return;
            }

            var zipPath = Path.Combine(parentDir, "Stelark.zip");

            try
            {
                if (File.Exists(zipPath))
                {
                    File.Delete(zipPath);
                }

                ZipFile.CreateFromDirectory(_state.OutputDir, zipPath);
                Directory.Delete(_state.OutputDir, true);

                ConsoleHelper.WriteInfo($"All Stelark output files have been zipped to: {zipPath}");
            }
            catch (Exception ex)
            {
                Logger.LogError("Failed to create or clean up zip archive", ex);
                ConsoleHelper.WriteError($"Failed to create or clean up zip archive: {ex.Message}");
            }
        }

        private void PrintFullFindings()
        {
            PrintESC1Templates();
            PrintESC2Templates();
            PrintESC3Templates();
            PrintESC4Templates();
            PrintESC6CAs();
            PrintESC7CAs();
            PrintESC8Endpoints();
            PrintCertificates();
            PrintIntenseFindings();
        }

        private void PrintIntenseFindings()
        {
            if (_state.IntenseUniqueCertificates.Count > 0)
            {
                if (_state.AllowIntenseFallback)
                {
                    ConsoleHelper.WriteInfo("Certificate analysis completed in offline mode. Template and CA-level checks require Active Directory connectivity.");
                }

                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine("==================== INTENSE SUSPICIOUS CERTIFICATES ====================");
                Console.ResetColor();

                int i = 1;
                foreach (var cert in _state.IntenseUniqueCertificates)
                {
                    PrintCertificateDetails(cert, i);
                    i++;
                }
            }
        }

        private void PrintESC1Templates()
        {
            if (_state.ESC1VulnTemplates.Count > 0)
            {
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine("==================== VULNERABLE ESC1 CERTIFICATE TEMPLATES ====================");
                Console.ResetColor();

                foreach (var template in _state.ESC1VulnTemplates)
                {
                    PrintTemplateDetails(template, "ESC1");
                }
            }
        }

        private void PrintESC2Templates()
        {
            if (_state.ESC2VulnTemplates.Count > 0)
            {
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine("==================== VULNERABLE ESC2 CERTIFICATE TEMPLATES ====================");
                Console.ResetColor();

                foreach (var template in _state.ESC2VulnTemplates)
                {
                    PrintTemplateDetails(template, "ESC2");
                }
            }
        }

        private void PrintESC3Templates()
        {
            if (_state.ESC3VulnTemplates.Count > 0)
            {
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine("==================== VULNERABLE ESC3 CERTIFICATE TEMPLATES ====================");
                Console.ResetColor();

                foreach (var template in _state.ESC3VulnTemplates)
                {
                    PrintTemplateDetails(template, "ESC3");
                }
            }
        }

        private void PrintESC4Templates()
        {
            if (_state.ESC4VulnTemplates.Count > 0)
            {
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine("==================== VULNERABLE ESC4 CERTIFICATE TEMPLATES ====================");
                Console.ResetColor();

                foreach (var template in _state.ESC4VulnTemplates)
                {
                    Console.WriteLine();
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"Certificate Template #{template.TemplateCount}");
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine("----------------------------------------");
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.Write("Template Name: ");
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.WriteLine(template.CN);
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.Write("Template Status: ");
                    Console.ForegroundColor = template.IsEnabled ? ConsoleColor.Green : ConsoleColor.Red;
                    Console.WriteLine(template.IsEnabled ? "Enabled (published to a CA)" : "Disabled (not published to any CA)");
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.Write("Vulnerability: ");
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Unprivileged users have dangerous permissions on the certificate template.");
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine("Risky Groups and Permissions:");
                    
                    foreach (var riskyGroup in template.RiskyGroups)
                    {
                        var accountName = riskyGroup.Group.Split('\\').LastOrDefault() ?? riskyGroup.Group;
                        var accountType = Stelark.Helpers.AdHelper.GetAccountType(accountName);
                        var label = accountType == Stelark.Helpers.AccountType.Group ? "Group" : "Account";
                        
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"  - {label}: {riskyGroup.Group}");
                        Console.ForegroundColor = ConsoleColor.White;
                        Console.WriteLine($"    Permissions: {riskyGroup.Rights}");
                    }
                    Console.ResetColor();
                }
            }
        }

        private void PrintESC6CAs()
        {
            if (_state.ESC6VulnCAs.Count > 0)
            {
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine("==================== ESC6 VULNERABLE CERTIFICATE AUTHORITIES ====================");
                Console.ResetColor();

                int i = 1;
                foreach (var ca in _state.ESC6VulnCAs)
                {
                    Console.WriteLine();
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"Vulnerable CA #{i}");
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine("----------------------------------------");
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.Write($"{"CA Server:",-22}");
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.WriteLine(ca.Server);
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.Write($"{"Vulnerability:",-22}");
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine(ca.VulnerabilityType);
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.Write($"{"Edit Flags Value:",-22}");
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.WriteLine(ca.EditFlags);
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.Write($"{"Description:",-22}");
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine(ca.Description);
                    Console.ResetColor();
                    i++;
                }
            }
        }

        private void PrintESC7CAs()
        {
            if (_state.ESC7VulnCAPermissions.Count > 0)
            {
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine("==================== ESC7 DANGEROUS CA PERMISSIONS ====================");
                Console.ResetColor();

                int i = 1;
                foreach (var permission in _state.ESC7VulnCAPermissions)
                {
                    Console.WriteLine();
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"Dangerous Permission #{i}");
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine("----------------------------------------");
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.Write($"{"CA Server:",-22}");
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.WriteLine(permission.Server);
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.Write($"{"Vulnerability:",-22}");
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine(permission.VulnerabilityType);
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.Write($"{"Principal:",-22}");
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine(permission.Principal);
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.Write($"{"Permission:",-22}");
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine(permission.Permission);
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.Write($"{"Is Privileged:",-22}");
                    Console.ForegroundColor = permission.IsPrivilegedAccount ? ConsoleColor.Green : ConsoleColor.Red;
                    Console.WriteLine(permission.IsPrivilegedAccount ? "Yes" : "No");
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.Write($"{"Description:",-22}");
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine(permission.Description);
                    Console.ResetColor();
                    i++;
                }
            }
        }

        private void PrintESC8Endpoints()
        {
            if (_state.ESC8VulnEndpoints.Count > 0)
            {
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine("==================== ESC8 VULNERABLE ENDPOINTS ====================");
                Console.ResetColor();

                int i = 1;
                foreach (var endpoint in _state.ESC8VulnEndpoints)
                {
                    Console.WriteLine();
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"Endpoint #{i}");
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine("----------------------------------------");
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.Write($"{"CA Server:",-22}");
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.WriteLine(endpoint.Server);
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.Write($"{"URL:",-22}");
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.WriteLine(endpoint.URL);
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.Write($"{"Web Enrollment:",-22}");
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Enabled");
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.Write($"{"NTLM authentication:",-22}");
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Enabled");
                    Console.ResetColor();
                    i++;
                }
            }
        }

        private void PrintCertificates()
        {
            if (_state.SuspiciousESC1CertCount > 0)
            {
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine("==================== SUSPICIOUS ESC1 CERTIFICATES ====================");
                Console.ResetColor();

                int i = 1;
                foreach (var cert in _state.ESC1Certificates.Where(c => c.IsSuspicious))
                {
                    PrintCertificateDetails(cert, i);
                    i++;
                }
            }

            if (_state.SuspiciousESC2CertCount > 0)
            {
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine("==================== SUSPICIOUS ESC2 CERTIFICATES ====================");
                Console.ResetColor();

                int i = 1;
                foreach (var cert in _state.ESC2Certificates.Where(c => c.IsSuspicious))
                {
                    PrintCertificateDetails(cert, i);
                    i++;
                }
            }

            if (_state.SuspiciousESC3CertCount > 0)
            {
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine("==================== SUSPICIOUS ESC3 CERTIFICATES ====================");
                Console.ResetColor();

                int i = 1;
                foreach (var cert in _state.ESC3Certificates.Where(c => c.IsSuspicious))
                {
                    PrintCertificateDetails(cert, i);
                    i++;
                }
            }

            if (_state.SuspiciousESC4CertCount > 0)
            {
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine("==================== SUSPICIOUS ESC4 CERTIFICATES ====================");
                Console.ResetColor();

                int i = 1;
                foreach (var cert in _state.ESC4Certificates.Where(c => c.IsSuspicious))
                {
                    PrintCertificateDetails(cert, i);
                    i++;
                }
            }
        }

        private void PrintTemplateDetails(VulnerableTemplate template, string escType)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"Certificate Template #{template.TemplateCount}");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("----------------------------------------");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write("Template Name: ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(template.CN);
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write("Template Status: ");
            Console.ForegroundColor = template.IsEnabled ? ConsoleColor.Green : ConsoleColor.Red;
            Console.WriteLine(template.IsEnabled ? "Enabled (published to a CA)" : "Disabled (not published to any CA)");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("Vulnerability Criteria:");
            
            if (escType == "ESC1")
            {
                // ESC1 specific criteria (needs SuppliesSubject)
                Console.ForegroundColor = ConsoleColor.DarkCyan;
                Console.Write("  - Enrollee Supplies Subject: ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine(template.SuppliesSubject);
                Console.ForegroundColor = ConsoleColor.DarkCyan;
                Console.Write("  - No Manager Approval: ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine(template.NoManagerApproval);
                Console.ForegroundColor = ConsoleColor.DarkCyan;
                Console.Write("  - No RA Signature: ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine(template.NoRASignature);
                Console.ForegroundColor = ConsoleColor.DarkCyan;
                Console.Write("  - Has Authentication EKU: ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine(template.HasAuthEKU);
                Console.ForegroundColor = ConsoleColor.DarkCyan;
                Console.Write("  - Has Enrollment Rights: ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine(template.HasEnroll);
            }
            else if (escType == "ESC2")
            {
                // ESC2 specific criteria (no SuppliesSubject needed)
                Console.ForegroundColor = ConsoleColor.DarkCyan;
                Console.Write("  - No Manager Approval: ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine(template.NoManagerApproval);
                Console.ForegroundColor = ConsoleColor.DarkCyan;
                Console.Write("  - No RA Signature: ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine(template.NoRASignature);
                Console.ForegroundColor = ConsoleColor.DarkCyan;
                Console.Write("  - Has Any Purpose EKU: ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine(template.HasAnyPurposeEKU);
                Console.ForegroundColor = ConsoleColor.DarkCyan;
                Console.Write("  - Has No EKU: ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine(template.HasNoEKU);
                Console.ForegroundColor = ConsoleColor.DarkCyan;
                Console.Write("  - Has Enrollment Rights: ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine(template.HasEnroll);
            }
            else if (escType == "ESC3")
            {
                // ESC3 specific criteria (no SuppliesSubject needed)
                Console.ForegroundColor = ConsoleColor.DarkCyan;
                Console.Write("  - No Manager Approval: ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine(template.NoManagerApproval);
                Console.ForegroundColor = ConsoleColor.DarkCyan;
                Console.Write("  - No RA Signature: ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine(template.NoRASignature);
                Console.ForegroundColor = ConsoleColor.DarkCyan;
                Console.Write("  - Has Certificate Request Agent EKU: ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine(template.HasCertRequestAgentEKU);
                Console.ForegroundColor = ConsoleColor.DarkCyan;
                Console.Write("  - Has Enrollment Rights: ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine(template.HasEnroll);
            }
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"{escType} Risky Enrollment Group");
            
            foreach (var group in template.EnrollmentGroups)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"  - {group}");
            }
            Console.ResetColor();
        }

        private void PrintCertificateDetails(Certificate cert, int certNumber)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"Certificate #{certNumber}");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("----------------------------------------");
            Console.ResetColor();

            var decID = cert.RequestID.NormalizeRequestID();

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write($"{"Request ID",-40}: ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(string.IsNullOrEmpty(decID) ? "N/A" : decID);

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write($"{"Requester Name",-40}: ");
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(string.IsNullOrEmpty(cert.Requester) ? "N/A" : cert.Requester);

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write($"{"Subject Alternative Name",-40}: ");
            Console.ForegroundColor = ConsoleColor.Red;
            var sanDisplay = cert.ContainsSAN ? cert.SANUPN : "N/A";
            Console.WriteLine(sanDisplay);

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write($"{"Certificate Template Name",-40}: ");
            Console.ForegroundColor = ConsoleColor.White;
            var templateName = !string.IsNullOrEmpty(cert.Template) ? cert.Template :
                              (!string.IsNullOrEmpty(cert.TemplateName) ? cert.TemplateName : "N/A");
            Console.WriteLine(templateName);

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write($"{"Certificate Request Status",-40}: ");
            var status = string.IsNullOrEmpty(cert.DispositionMsg) ? "N/A" : cert.DispositionMsg;
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine(status);

            var fields = new[]
            {
                ("Requested Date", cert.SubmissionDate),
                ("Certificate Effective Date", cert.NotBefore),
                ("Certificate Expiration Date", cert.NotAfter),
                ("Certificate Serial Number", cert.Serial),
                ("Certificate Hash", cert.CertHash)
            };

            foreach (var (label, value) in fields)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.Write($"{label,-40}: ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine(string.IsNullOrEmpty(value) ? "N/A" : value);
            }

            Console.ResetColor();
        }

        private void PrintFullSummary()
        {
            if (_state.FoundCAServers && !_state.IsLocalCAServer)
            {
                var caList = _state.CAServerHostnames.Count > 0 ? 
                    string.Join(", ", _state.CAServerHostnames) : "the CA server";
                ConsoleHelper.WriteWarning($"Run Stelark on the CA server ({caList}) for complete analysis.");
                return;
            }

            if (!_state.FoundCAServers)
            {
                ConsoleHelper.WriteWarning("No CA infrastructure detected. No further checks were performed.");
            }
            else
            {
                PrintTemplateSummary();
                PrintESC6Summary();
                PrintESC7Summary();
                PrintESC8Summary();
                PrintCertificateSummary();
            }
        }

        private void PrintIntenseSummary()
        {
            ConsoleHelper.WriteInfo("Certificate analysis completed in offline mode. Template and CA-level checks require Active Directory connectivity.");

            if (_state.IntenseUniqueCertificates.Count > 0)
            {
                ConsoleHelper.WriteWarning($"Identified {_state.IntenseUniqueCertificates.Count} Suspicious Certificate(s) via Intense Mode.");
            }
            else
            {
                if (_state.CertutilErrorDetected_Intense)
                {
                    ConsoleHelper.WriteError("Intense Mode Certificate Enumeration Process Failed. Certificate Enumeration May be Incomplete or Inaccurate.");
                }
                else
                {
                    ConsoleHelper.WriteSuccess("No Suspicious Certificates Were Identified via Intense Mode.");
                }
            }
        }

        private void PrintTemplateSummary()
        {
            var templateSummaries = new[]
            {
                ("ESC1", _state.ESC1VulnTemplates.Count),
                ("ESC2", _state.ESC2VulnTemplates.Count),
                ("ESC3", _state.ESC3VulnTemplates.Count),
                ("ESC4", _state.ESC4VulnTemplates.Count)
            };

            foreach (var (escType, count) in templateSummaries)
            {
                if (count > 0)
                {
                    ConsoleHelper.WriteWarning($"Found {count} Certificate Template(s) Vulnerable to {escType}.");
                }
                else
                {
                    ConsoleHelper.WriteSuccess($"No Certificate Templates Vulnerable to {escType} Were Found.");
                }
            }
        }

        private void PrintCertificateSummary()
        {
            var certSummaries = new[]
            {
                ("ESC1", _state.SuspiciousESC1CertCount, _state.ESC1VulnTemplates.Count > 0, _state.CertutilErrorDetected_ESC1),
                ("ESC2", _state.SuspiciousESC2CertCount, _state.ESC2VulnTemplates.Count > 0, _state.CertutilErrorDetected_ESC2),
                ("ESC3", _state.SuspiciousESC3CertCount, _state.ESC3VulnTemplates.Count > 0, _state.CertutilErrorDetected_ESC3),
                ("ESC4", _state.SuspiciousESC4CertCount, _state.ESC4VulnTemplates.Count > 0, _state.CertutilErrorDetected_ESC4)
            };

            foreach (var (escType, count, hasTemplates, errorDetected) in certSummaries)
            {
                if (count > 0)
                {
                    ConsoleHelper.WriteWarning($"Identified {count} Suspicious Certificate(s) Issued via {escType}-Vulnerable Templates.");
                }
                else if (hasTemplates)
                {
                    if (errorDetected)
                    {
                        ConsoleHelper.WriteError($"{escType} Certificate Enumeration Process Failed. Certificate Enumeration May be Incomplete or Inaccurate.");
                    }
                    else
                    {
                        ConsoleHelper.WriteSuccess($"No Suspicious Certificates Issued via {escType}-Vulnerable Templates Were Identified.");
                    }
                }
            }

            // Intense mode summary
            if (_state.IntenseScanRun)
            {
                if (_state.IntenseUniqueCertificates.Count > 0)
                {
                    ConsoleHelper.WriteWarning($"Identified {_state.IntenseUniqueCertificates.Count} Suspicious Certificate(s) via Intense Mode.");
                }
                else
                {
                    if (_state.CertutilErrorDetected_Intense)
                    {
                        ConsoleHelper.WriteError("Intense Mode Certificate Enumeration Process Failed. Certificate Enumeration May be Incomplete or Inaccurate.");
                    }
                    else
                    {
                        ConsoleHelper.WriteSuccess("No Suspicious Certificates Were Identified via Intense Mode.");
                    }
                }
            }
            else
            {
                ConsoleHelper.WriteInfo("Intense mode scan was skipped. For a comprehensive analysis, re-run the scan with the --intense flag.");
            }
        }

        private void PrintESC6Summary()
        {
            if (_state.ESC6VulnCAs.Count > 0)
            {
                ConsoleHelper.WriteWarning($"Found {_state.ESC6VulnCAs.Count} Certificate Authority(s) Vulnerable to ESC6.");
            }
            else
            {
                ConsoleHelper.WriteSuccess("No Certificate Authorities Vulnerable to ESC6 Were Found.");
            }
        }

        private void PrintESC7Summary()
        {
            if (_state.ESC7VulnCAPermissions.Count > 0)
            {
                var lowPrivCount = _state.ESC7VulnCAPermissions.Count(p => !p.IsPrivilegedAccount);
                if (lowPrivCount > 0)
                {
                    ConsoleHelper.WriteWarning($"Found {lowPrivCount} Dangerous CA Permission(s) Granted to Low-Privileged Principals (ESC7).");
                }
                else
                {
                    ConsoleHelper.WriteSuccess("All Dangerous CA Permissions are Granted to Appropriately Privileged Principals.");
                }
            }
            else
            {
                ConsoleHelper.WriteSuccess("No Dangerous CA Permissions Related to ESC7 Were Found.");
            }
        }

        private void PrintESC8Summary()
        {
            if (_state.ESC8VulnEndpoints.Count > 0)
            {
                ConsoleHelper.WriteWarning($"Found {_state.ESC8VulnEndpoints.Count} Vulnerable Endpoint(s) Related to ESC8.");
            }
            else
            {
                ConsoleHelper.WriteSuccess("No Endpoints Vulnerable Related to ESC8 Were Found.");
            }
        }
    }
} 