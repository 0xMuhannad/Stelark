using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

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
            Console.WriteLine("==================== SUMMARY ====================");
            Console.ResetColor();

            if (intenseOnly)
            {
                PrintIntenseSummary();
            }
            else
            {
                PrintFullSummary();
            }

            Console.WriteLine("=================================================");
        }

        public async Task SaveFindingsAsync(bool intenseOnly)
        {
            var outputDir = _state.OutputDir;
            Directory.CreateDirectory(outputDir);
            
            Logger.LogInfo($"Saving findings to: {outputDir}");
            Logger.LogInfo($"Intense Mode Only: {intenseOnly}");

            SaveIndividualCertificateFiles(outputDir, intenseOnly);
            await SaveIndividualTemplateFilesAsync(outputDir, intenseOnly);

            await SaveCsvReports(outputDir, intenseOnly);
            Logger.LogFileOperation("Generated", "CSV Reports", "Success");

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
            // Only save suspicious certificates to individual files
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

        private async Task SaveCsvReports(string outputDir, bool intenseOnly)
        {

            var allSuspiciousCerts = new List<Certificate>();
            if (!intenseOnly)
            {
                allSuspiciousCerts.AddRange(_state.ESC1Certificates.Where(c => c.IsSuspicious));
                allSuspiciousCerts.AddRange(_state.ESC2Certificates.Where(c => c.IsSuspicious));
                allSuspiciousCerts.AddRange(_state.ESC3Certificates.Where(c => c.IsSuspicious));
                allSuspiciousCerts.AddRange(_state.ESC4Certificates.Where(c => c.IsSuspicious));
            }
            allSuspiciousCerts.AddRange(_state.IntenseUniqueCertificates);

            await WriteCsvAsync(Path.Combine(outputDir, "Suspicious_Certificates.csv"), allSuspiciousCerts.Distinct(), WriteCertificateCsvHeader, WriteCertificateCsvRow);
        }
        
        private async Task SaveJsonReport(string outputDir, bool intenseOnly)
        {
            var jsonPath = Path.Combine(outputDir, "Stelark_findings.json");
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
            var htmlPath = Path.Combine(outputDir, "Stelark_Report.html");
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

        private async Task WriteCsvAsync<T>(string path, IEnumerable<T> items, Action<StreamWriter> headerWriter, Action<StreamWriter, T> rowWriter)
        {
            if (!items.Any()) return;
            using var writer = new StreamWriter(path);
            headerWriter(writer);
            foreach (var item in items)
            {
                rowWriter(writer, item);
            }
            await writer.FlushAsync();
        }
        
        private void WriteCertificateCsvHeader(StreamWriter writer)
        {
            writer.WriteLine("Source,RequestID,Requester,SubjectAlternativeName,IsSuspicious,TemplateName,Status,SubmissionDate,EffectiveDate,ExpirationDate,Serial,CertHash");
        }

        private void WriteCertificateCsvRow(StreamWriter writer, Certificate cert)
        {
            var sanValue = cert.ContainsSAN ? cert.SANUPN : "N/A";
            writer.WriteLine($"\"{cert.Source}\",\"{cert.RequestID.NormalizeRequestID()}\",\"{cert.Requester}\",\"{sanValue}\",\"{cert.IsSuspicious}\",\"{cert.Template}\",\"{cert.DispositionMsg}\",\"{cert.SubmissionDate}\",\"{cert.NotBefore}\",\"{cert.NotAfter}\",\"{cert.Serial}\",\"{cert.CertHash}\"");
        }

        private object BuildJsonFindings(bool intenseOnly)
        {
            var result = new Dictionary<string, object>
            {
                ["Stelark"] = new Dictionary<string, object>()
            };
            
            var stelarkFindings = (Dictionary<string, object>)result["Stelark"];

            // Check if no CA infrastructure was found
            if (!_state.FoundCAServers)
            {
                stelarkFindings["Analysis_Status"] = "No CA Infrastructure Detected";
                stelarkFindings["CA_Discovery_Result"] = "No Certificate Authority servers found in Active Directory";
                stelarkFindings["Connectivity_Status"] = "AD connectivity may be limited or no ADCS infrastructure deployed";
                stelarkFindings["Checks_Performed"] = new[] { "CA Discovery" };
                stelarkFindings["Vulnerability_Analysis"] = "Not performed - no Certificate Authority infrastructure detected";
                stelarkFindings["Certificate_Analysis"] = "Not performed - no Certificate Authority infrastructure detected";
                stelarkFindings["Recommendation"] = "Ensure Active Directory connectivity and verify ADCS infrastructure is deployed";
                
                return result;
            }

            // Check if running on non-CA server
            if (_state.FoundCAServers && !_state.IsLocalCAServer)
            {
                var caList = _state.CAServerHostnames.Count > 0 ? 
                    string.Join(", ", _state.CAServerHostnames) : "the CA server";
                
                stelarkFindings["Analysis_Status"] = "Limited Analysis - Not run on CA server";
                stelarkFindings["CA_Servers_Discovered"] = _state.CAServerHostnames.ToArray();
                stelarkFindings["Recommendation"] = $"Run Stelark directly on the CA server ({caList}) for complete ADCS security assessment";
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
                CertHash = cert.CertHash
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
            var caNames = _state.CAServerHostnames.Count > 0 ? 
                string.Join(", ", _state.CAServerHostnames) : 
                (!_state.FoundCAServers ? "No CA Infrastructure Detected" : "Not Available");
            

            var allCertificates = new List<Certificate>();
            var vulnerabilityStats = new Dictionary<string, int>();
            
            if (!intenseOnly)
            {
                allCertificates.AddRange(_state.ESC1Certificates.Where(c => c.IsSuspicious));
                allCertificates.AddRange(_state.ESC2Certificates.Where(c => c.IsSuspicious));
                allCertificates.AddRange(_state.ESC3Certificates.Where(c => c.IsSuspicious));
                allCertificates.AddRange(_state.ESC4Certificates.Where(c => c.IsSuspicious));
                
                vulnerabilityStats["ESC1_Templates"] = _state.ESC1VulnTemplates.Count;
                vulnerabilityStats["ESC2_Templates"] = _state.ESC2VulnTemplates.Count;
                vulnerabilityStats["ESC3_Templates"] = _state.ESC3VulnTemplates.Count;
                vulnerabilityStats["ESC4_Templates"] = _state.ESC4VulnTemplates.Count;
                vulnerabilityStats["ESC6_CAs"] = _state.ESC6VulnCAs.Count;
                vulnerabilityStats["ESC7_Permissions"] = _state.ESC7VulnCAPermissions.Count;
                vulnerabilityStats["ESC8_Endpoints"] = _state.ESC8VulnEndpoints.Count;
            }
            
            allCertificates.AddRange(_state.IntenseUniqueCertificates);
            var totalVulnerabilities = vulnerabilityStats.Values.Sum();
            var totalCertificates = allCertificates.Count;

            return $@"<!DOCTYPE html>
<html lang=""en"">
<head>
    <meta charset=""UTF-8"">
    <meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">
    <title>Stelark ADCS Security Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #2c3e50 100%);
            color: #333;
            line-height: 1.6;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }}

        .header {{
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
            text-align: center;
        }}

        .header h1 {{
            color: #2c3e50;
            font-size: 2.5rem;
            margin-bottom: 10px;
            background: linear-gradient(45deg, #667eea, #2c3e50);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}

        .header .subtitle {{
            color: #7f8c8d;
            font-size: 1.2rem;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}

        .stat-card {{
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            padding: 25px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }}

        .stat-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.2);
        }}

        .stat-number {{
            font-size: 2.5rem;
            font-weight: bold;
            color: #e74c3c;
            margin-bottom: 10px;
        }}

        .stat-label {{
            color: #7f8c8d;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}

        .section {{
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        }}

        .section h2 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
            margin-bottom: 25px;
            font-size: 1.8rem;
        }}

        .filters {{
            display: flex;
            gap: 15px;
            margin-bottom: 25px;
            flex-wrap: wrap;
        }}

        .filter-input {{
            padding: 12px 15px;
            border: 2px solid #e0e6ed;
            border-radius: 8px;
            font-size: 14px;
            transition: border-color 0.3s ease;
            flex: 1;
            min-width: 200px;
        }}

        .filter-input:focus {{
            outline: none;
            border-color: #3498db;
        }}

        .btn {{
            padding: 12px 20px;
            background: linear-gradient(45deg, #3498db, #2980b9);
            color: white;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.3s ease;
        }}

        .btn:hover {{
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(52, 152, 219, 0.4);
        }}

        .table-container {{
            overflow-x: auto;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.1);
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
        }}

        th {{
            background: linear-gradient(45deg, #34495e, #2c3e50);
            color: white;
            padding: 15px 12px;
            text-align: left;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.3s ease;
        }}

        th:hover {{
            background: linear-gradient(45deg, #2c3e50, #34495e);
        }}

        td {{
            padding: 12px;
            border-bottom: 1px solid #e0e6ed;
            transition: background 0.3s ease;
        }}

        tr:hover td {{
            background: #f8f9fa;
        }}

        .vulnerability-badge {{
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: bold;
            text-transform: uppercase;
        }}

        .esc1 {{ background: #e74c3c; color: white; }}
        .esc2 {{ background: #f39c12; color: white; }}
        .esc3 {{ background: #9b59b6; color: white; }}
        .esc4 {{ background: #e67e22; color: white; }}
        .esc6 {{ background: #2ecc71; color: white; }}
        .esc7 {{ background: #1abc9c; color: white; }}
        .esc8 {{ background: #34495e; color: white; }}
        .intense {{ background: #c0392b; color: white; }}

        .eku-badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
            background: #3498db;
            color: white;
        }}

        .permission-badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 8px;
            font-size: 0.7rem;
            font-weight: 600;
            margin: 2px;
            background: #95a5a6;
            color: white;
        }}

        .permission-badge.danger {{
            background: #e74c3c;
        }}

        .permission-badge.warning {{
            background: #f39c12;
        }}

        .permission-badge.info {{
            background: #3498db;
        }}

        .chart-container {{
            margin: 30px 0;
            padding: 30px;
            background: white;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
            position: relative;
        }}

        .chart {{
            width: 100%;
            height: 400px;
            position: relative;
        }}

        .chart-title {{
            font-size: 20px;
            font-weight: 600;
            color: #2c3e50;
            margin-bottom: 20px;
            text-align: center;
        }}

        .summary-info {{
            background: #ecf0f1;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            border-left: 5px solid #3498db;
        }}

        .no-data {{
            text-align: center;
            padding: 50px;
            color: #7f8c8d;
            font-style: italic;
        }}

        @media (max-width: 768px) {{
            .container {{
                padding: 10px;
            }}
            
            .header h1 {{
                font-size: 2rem;
            }}
            
            .filters {{
                flex-direction: column;
            }}
            
            .stats-grid {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class=""container"">
        <div class=""header"">
            <h1>🛡️ Stelark ADCS Security Report</h1>
            <div class=""subtitle"">
                Comprehensive Active Directory Certificate Services Assessment<br>
                <em style=""color: #7f8c8d; font-style: italic;"">The Ark that hunts the stars</em><br>
                Generated: {timestamp} | Scan Type: {scanType}<br>
                CA Name: {caNames}
            </div>
        </div>

        <div class=""stats-grid"">
            <div class=""stat-card"">
                <div class=""stat-number"">{totalVulnerabilities}</div>
                <div class=""stat-label"">Total Vulnerabilities</div>
            </div>
            <div class=""stat-card"">
                <div class=""stat-number"">{totalCertificates}</div>
                <div class=""stat-label"">Suspicious Certificates</div>
            </div>
            <div class=""stat-card"">
                <div class=""stat-number"">{_state.CAServerHostnames.Count}</div>
                <div class=""stat-label"">CA Servers Found</div>
            </div>
            <div class=""stat-card"">
                <div class=""stat-number"">{GetChecksPerformedCount(intenseOnly)}</div>
                <div class=""stat-label"">Checks Performed</div>
            </div>
        </div>

        {(intenseOnly ? GenerateIntenseReportContent() : GenerateFullReportContent())}
    </div>

    <script>
        
        function sortTable(table, column, asc = true) {{
            const dirModifier = asc ? 1 : -1;
            const tBody = table.tBodies[0];
            const rows = Array.from(tBody.querySelectorAll('tr'));

            const sortedRows = rows.sort((a, b) => {{
                const aColText = a.querySelector(`td:nth-child(${{column + 1}})`).textContent.trim();
                const bColText = b.querySelector(`td:nth-child(${{column + 1}})`).textContent.trim();

                return aColText > bColText ? (1 * dirModifier) : (-1 * dirModifier);
            }});

            while (tBody.firstChild) {{
                tBody.removeChild(tBody.firstChild);
            }}

            tBody.append(...sortedRows);
        }}


        document.querySelectorAll('table').forEach(table => {{
            const headers = table.querySelectorAll('th');
            headers.forEach((header, index) => {{
                let asc = true;
                header.addEventListener('click', () => {{
                    sortTable(table, index, asc);
                    asc = !asc;
                }});
            }});
        }});


        function filterTable(tableId, searchValue) {{
            const table = document.getElementById(tableId);
            if (!table) return;
            
            const rows = table.getElementsByTagName('tr');
            searchValue = searchValue.toLowerCase();

            for (let i = 1; i < rows.length; i++) {{
                let found = false;
                const cells = rows[i].getElementsByTagName('td');
                
                for (let j = 0; j < cells.length; j++) {{
                    if (cells[j].textContent.toLowerCase().includes(searchValue)) {{
                        found = true;
                        break;
                    }}
                }}
                
                rows[i].style.display = found ? '' : 'none';
            }}
        }}


        document.querySelectorAll('.filter-input').forEach(input => {{
            input.addEventListener('keyup', function() {{
                const tableId = this.getAttribute('data-table');
                filterTable(tableId, this.value);
            }});
        }});




        // Chart.js configuration
        function generateChart() {{
            const ctx = document.getElementById('vulnChart');
            if (!ctx) return;
            
            const data = {JsonSerializer.Serialize(vulnerabilityStats)};
            const labels = Object.keys(data).map(key => key.replace('_', ' '));
            const values = Object.values(data);
            
            // Modern color palette with gradients
            const colors = [
                {{ bg: 'rgba(231, 76, 60, 0.8)', border: 'rgba(231, 76, 60, 1)' }},   // ESC1 - Red
                {{ bg: 'rgba(243, 156, 18, 0.8)', border: 'rgba(243, 156, 18, 1)' }}, // ESC2 - Orange  
                {{ bg: 'rgba(155, 89, 182, 0.8)', border: 'rgba(155, 89, 182, 1)' }}, // ESC3 - Purple
                {{ bg: 'rgba(230, 126, 34, 0.8)', border: 'rgba(230, 126, 34, 1)' }}, // ESC4 - Dark Orange
                {{ bg: 'rgba(46, 204, 113, 0.8)', border: 'rgba(46, 204, 113, 1)' }}, // ESC6 - Green
                {{ bg: 'rgba(26, 188, 156, 0.8)', border: 'rgba(26, 188, 156, 1)' }}, // ESC7 - Teal
                {{ bg: 'rgba(52, 73, 94, 0.8)', border: 'rgba(52, 73, 94, 1)' }}      // ESC8 - Dark Blue
            ];
            
            if (values.length === 0 || Math.max(...values) === 0) {{
                ctx.style.display = 'none';
                const container = ctx.parentElement;
                container.innerHTML = '<div style=""text-align: center; padding: 40px; color: #27ae60;""><div style=""font-size: 48px; margin-bottom: 16px;"">🛡️</div><h3 style=""color: #27ae60; margin: 0;"">No Vulnerabilities Detected</h3><p style=""color: #7f8c8d; margin: 8px 0 0 0;"">Your ADCS infrastructure appears to be secure!</p></div>';
                return;
            }}
            
            new Chart(ctx, {{
                type: 'bar',
                data: {{
                    labels: labels,
                    datasets: [{{
                        label: 'Vulnerabilities',
                        data: values,
                        backgroundColor: colors.slice(0, values.length).map(c => c.bg),
                        borderColor: colors.slice(0, values.length).map(c => c.border),
                        borderWidth: 2,
                        borderRadius: 8,
                        borderSkipped: false,
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{
                            display: false
                        }},
                        tooltip: {{
                            backgroundColor: 'rgba(44, 62, 80, 0.95)',
                            titleColor: '#ffffff',
                            bodyColor: '#ffffff',
                            borderColor: '#34495e',
                            borderWidth: 1,
                            cornerRadius: 8,
                            displayColors: true,
                            callbacks: {{
                                title: function(context) {{
                                    return context[0].label + ' Vulnerabilities';
                                }},
                                label: function(context) {{
                                    const value = context.parsed.y;
                                    return value === 1 ? '1 vulnerability found' : value + ' vulnerabilities found';
                                }}
                            }}
                        }}
                    }},
                    scales: {{
                        y: {{
                            beginAtZero: true,
                            ticks: {{
                                stepSize: 1,
                                color: '#7f8c8d',
                                font: {{
                                    family: 'Segoe UI, Tahoma, Geneva, Verdana, sans-serif',
                                    size: 12
                                }}
                            }},
                            grid: {{
                                color: 'rgba(127, 140, 141, 0.1)',
                                borderColor: 'rgba(127, 140, 141, 0.2)'
                            }}
                        }},
                        x: {{
                            ticks: {{
                                color: '#2c3e50',
                                font: {{
                                    family: 'Segoe UI, Tahoma, Geneva, Verdana, sans-serif',
                                    size: 12,
                                    weight: '600'
                                }}
                            }},
                            grid: {{
                                display: false
                            }}
                        }}
                    }},
                    animation: {{
                        duration: 1200,
                        easing: 'easeOutQuart'
                    }},
                    interaction: {{
                        intersect: false,
                        mode: 'index'
                    }}
                }}
            }});
        }}

        // Load Chart.js and initialize
        document.addEventListener('DOMContentLoaded', function() {{
            const script = document.createElement('script');
            script.src = 'https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.js';
            script.onload = generateChart;
            document.head.appendChild(script);
        }});
    </script>
</body>
</html>";
        }

        private string GenerateFullReportContent()
        {
            var content = @"";
            
            // Vulnerability Distribution Chart - only show if there are actual vulnerabilities
            var totalVulnCount = _state.ESC1VulnTemplates.Count + _state.ESC2VulnTemplates.Count + 
                                _state.ESC3VulnTemplates.Count + _state.ESC4VulnTemplates.Count +
                                _state.ESC6VulnCAs.Count + _state.ESC7VulnCAPermissions.Count + 
                                _state.ESC8VulnEndpoints.Count;
            
            if (totalVulnCount > 0)
            {
                content += @"
        <div class=""section"">
            <h2>Vulnerability Distribution</h2>
            <div class=""chart-container"">
                <div class=""chart-title"">ADCS Security Assessment Results</div>
                <div class=""chart"">
                    <canvas id=""vulnChart""></canvas>
                </div>
            </div>
        </div>";
            }

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
                <strong>Risk:</strong> ADCS web enrollment endpoints that can be exploited.
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
            return $@"
        <div class=""section"">
            <h2>{title} ({certificates.Count})</h2>
            <div class=""filters"">
                <input type=""text"" class=""filter-input"" placeholder=""Search certificates..."" data-table=""{tableId}"">
            </div>
            <div class=""table-container"">
                <table id=""{tableId}"">
                    <thead>
                        <tr>
                            <th>Source</th>
                            <th>Request ID</th>
                            <th>Requester</th>
                            <th>SAN/UPN</th>
                            <th>Template</th>
                            <th>Serial Number</th>
                            <th>Submission Date</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        {string.Join("", certificates.Select(cert => $@"
                        <tr>
                            <td><span class=""vulnerability-badge {cert.Source.ToLower()}"">{cert.Source}</span></td>
                            <td>{cert.RequestID.NormalizeRequestID()}</td>
                            <td>{cert.Requester}</td>
                            <td>{(cert.ContainsSAN ? cert.SANUPN : "N/A")}</td>
                            <td>{cert.Template}</td>
                            <td>{cert.Serial}</td>
                            <td>{cert.SubmissionDate}</td>
                            <td>{cert.DispositionMsg}</td>
                        </tr>"))}
                    </tbody>
                </table>
            </div>
        </div>";
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
                    <li>No ADCS infrastructure deployed in the domain</li>
                    <li>Network or permission issues preventing CA discovery</li>
                </ul>
                <p><strong>Recommendation:</strong> Verify AD connectivity and ADCS deployment</p>
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
                <p><strong>For complete ADCS security assessment:</strong></p>
                <p>Run Stelark directly on the CA server: <strong>{caList}</strong></p>
            </div>
        </div>";
            }
            
            // Normal case - full analysis with no vulnerabilities
            return @"
        <div class=""section"">
            <div class=""no-data"">
                <h2>No Vulnerabilities Found</h2>
                <p>The scan completed successfully with no ADCS vulnerabilities detected.</p>
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
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"  - Group: {riskyGroup.Group}");
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
            Console.Write($"{"Requester Name (Source)",-40}: ");
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(string.IsNullOrEmpty(cert.Requester) ? "N/A" : cert.Requester);

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write($"{"Subject Alternative Name (Target)",-40}: ");
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
            Console.ForegroundColor = status == "Issued" ? ConsoleColor.Green : ConsoleColor.Red;
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
                ConsoleHelper.WriteInfo("Intense mode scan was skipped. For a comprehensive analysis, re-run the scan with the -Intense flag.");
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