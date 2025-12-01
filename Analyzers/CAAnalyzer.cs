using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Win32;
using Stelark.Core;
using Stelark.Models;
using Stelark.Helpers;
using Stelark.Services;
using AccountType = Stelark.Helpers.AccountType;

namespace Stelark.Analyzers
{
    public class CAAnalyzer : IDisposable
    {
        private readonly GlobalState _state;
        private readonly HttpClient _httpClient;

        public CAAnalyzer(GlobalState state)
        {
            _state = state;
            _httpClient = new HttpClient(new HttpClientHandler()
            {
                ServerCertificateCustomValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true
            });
            _httpClient.Timeout = TimeSpan.FromSeconds(30); // Increased timeout for large environments
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "Stelark/1.4");
        }

        public void FindCAServers()
        {
            ConsoleHelper.WriteInfo("Discovering Certificate Authority (CA) servers in the current domain...");
            Logger.LogInfo("Starting CA server discovery process");
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            
            try
            {
                var caServers = GetADCSCAServers();
                stopwatch.Stop();
                Logger.LogInfo($"CA server discovery completed in {stopwatch.ElapsedMilliseconds}ms");
                if (caServers.Count > 0)
                {
                    _state.FoundCAServers = true;
                    _state.CAServerHostnames = caServers;
                        
                    foreach (var caServer in caServers)
                    {
                        var ipAddress = ResolveCAServerIP(caServer);
                        var displayMessage = !string.IsNullOrEmpty(ipAddress) 
                            ? $"Found CA: {caServer} ({ipAddress})"
                            : $"Found CA: {caServer}";
                        
                        ConsoleHelper.WriteSuccess(displayMessage);
                        Logger.LogDiscovery("CA Server", $"{caServer} discovered in domain" + 
                            (!string.IsNullOrEmpty(ipAddress) ? $" (IP: {ipAddress})" : ""));
                    }
                }
                else
                {
                    _state.FoundCAServers = false;
                    Logger.LogQuery("CA Discovery", "Active Directory", 0);
                    Logger.LogInfo("No Certificate Authority servers found in the domain");
                    ConsoleHelper.WriteInfo("No Certificate Authority servers found in the domain.");
                }
            }
            catch (Exception ex)
            {
                Logger.LogError("Could not enumerate CA servers from AD", ex);
                ConsoleHelper.WriteError($"Could not enumerate CA servers from AD: {ex.Message}");
            }
        }

        public void TestIsLocalCAServer()
        {
            _state.IsLocalCAServer = false;
            _state.LocalCAServerName = string.Empty;
            
            if (!_state.FoundCAServers)
                return;

            try
            {
                var localFQDN = System.Net.Dns.GetHostEntry(Environment.MachineName).HostName.ToLower();
                var localHost = Environment.MachineName.ToLower();

                foreach (var server in _state.CAServerHostnames)
                {
                    if (server.ToLower() == localFQDN || server.ToLower() == localHost)
                    {
                        _state.IsLocalCAServer = true;
                        _state.LocalCAServerName = server;
                        break;
                    }
                }

                if (_state.FoundCAServers && !_state.IsLocalCAServer)
                {
                    ConsoleHelper.WriteWarning("CA servers were found but this machine is not a CA server. Stelark should be run on a CA server.");
                }
            }
            catch (Exception ex)
            {
                Logger.LogError("Failed to determine if local machine is CA server", ex);
                ConsoleHelper.WriteError($"Failed to determine if local machine is CA server: {ex.Message}");
            }
        }

        public async Task FindESC8VulnerableEndpointsAsync()
        {
            if (!_state.IsLocalCAServer)
            {
                _state.ESC8VulnEndpoints.Clear();
                _state.ESC8VulnCount = 0;
                return;
            }

            ConsoleHelper.WriteInfo("Enumerating vulnerable endpoints related to ESC8...");
            
            var caObjects = GetCAADObjectsWithDACLs();
            var caServers = new List<string>();

            if (caObjects != null)
            {
                foreach (SearchResult obj in caObjects)
                {
                    if (obj.Properties["dNSHostName"].Count > 0)
                    {
                        caServers.Add(obj.Properties["dNSHostName"][0].ToString()!);
                    }
                }
            }

            if (caServers.Count == 0)
            {
                ConsoleHelper.WriteError("No CA servers found for ESC8 check.");
                return;
            }

            var tasks = caServers.Select(CheckESC8EndpointAsync);
            var results = await Task.WhenAll(tasks);
            
            _state.ESC8VulnEndpoints = results.Where(r => r != null).ToList()!;
            _state.ESC8VulnCount = _state.ESC8VulnEndpoints.Count;
        }

        private async Task<VulnerableEndpoint?> CheckESC8EndpointAsync(string server)
        {
            var uri = $"http://{server}/certsrv/certfnsh.asp";
            
            try
            {
                var request = new HttpRequestMessage(HttpMethod.Head, uri);
                var response = await _httpClient.SendAsync(request);

                if (response.StatusCode == HttpStatusCode.Unauthorized)
                {
                    if (response.Headers.WwwAuthenticate?.Any(h => h.Scheme?.ToUpper() == "NTLM") == true)
                    {
                        return new VulnerableEndpoint
                        {
                            Server = server,
                            URL = uri
                        };
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.LogError($"ESC8 endpoint check failed for {server}", ex);
            }

            return null;
        }

        private List<string> GetADCSCAServers()
        {
            var caServers = new List<string>();
            
            try
            {
                var caObjects = GetCAADObjectsWithDACLs();
                if (caObjects != null)
                {
                    foreach (SearchResult obj in caObjects)
                    {
                        if (obj.Properties["dNSHostName"].Count > 0)
                        {
                            caServers.Add(obj.Properties["dNSHostName"][0].ToString()!);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.LogError("Could not enumerate CA servers from AD in GetADCSCAServers", ex);
                ConsoleHelper.WriteError($"Could not enumerate CA servers from AD: {ex.Message}");
            }

            return caServers;
        }

        private SearchResultCollection? GetCAADObjectsWithDACLs()
        {
            try
            {
                Logger.LogInfo("Attempting LDAP connection to Active Directory");
                DirectoryEntry? rootDSE = null;
                string? configNC = null;

                Logger.LogInfo("Trying LDAP connection method 1: Machine's domain (fast path)");
                string? domainName = null;
                    try
                    {
                        domainName = System.Net.Dns.GetHostEntry(Environment.MachineName).HostName;
                        if (domainName.Contains("."))
                        {
                            domainName = domainName.Substring(domainName.IndexOf(".") + 1);
                            rootDSE = new DirectoryEntry($"LDAP://{domainName}/RootDSE");
                            configNC = rootDSE.Properties["configurationNamingContext"]?[0]?.ToString();
                        Logger.LogInfo("LDAP connection method 1: SUCCESS");
                        }
                    }
                catch (Exception ex)
                    {
                    Logger.LogError($"LDAP connection method 1 failed (Domain: {domainName ?? "unknown"})", ex);
                    Logger.LogInfo("LDAP connection method 1: FAILED - Trying method 2: localhost");
                        try
                        {
                            rootDSE = new DirectoryEntry("LDAP://localhost/RootDSE");
                            configNC = rootDSE.Properties["configurationNamingContext"]?[0]?.ToString();
                        Logger.LogInfo("LDAP connection method 2: SUCCESS");
                        }
                    catch (Exception ex2)
                        {
                        Logger.LogError("LDAP connection method 2 failed", ex2);
                        Logger.LogInfo("LDAP connection method 2: FAILED - Trying method 3: Machine FQDN");
                            try
                            {
                                var machineName = Environment.MachineName;
                                var fqdn = System.Net.Dns.GetHostEntry(machineName).HostName;
                                
                                if (fqdn.Contains("."))
                                {
                                    var domain = fqdn.Substring(fqdn.IndexOf(".") + 1);
                                    var dcName = fqdn.Substring(0, fqdn.IndexOf("."));
                                    
                                    rootDSE = new DirectoryEntry($"LDAP://{fqdn}/RootDSE");
                                    configNC = rootDSE.Properties["configurationNamingContext"]?[0]?.ToString();
                                Logger.LogInfo("LDAP connection method 3: SUCCESS");
                            }
                        }
                        catch (Exception ex3)
                        {
                            Logger.LogError("LDAP connection method 3 failed", ex3);
                            Logger.LogInfo("LDAP connection method 3: FAILED - Trying method 4: RootDSE");
                            try
                            {
                                rootDSE = new DirectoryEntry("LDAP://RootDSE");
                                configNC = rootDSE.Properties["configurationNamingContext"]?[0]?.ToString();
                                Logger.LogInfo("LDAP connection method 4: SUCCESS");
                            }
                            catch (Exception ex4)
                            {
                                Logger.LogError("All LDAP connection methods failed for CA discovery - check network connectivity and AD permissions", ex4);
                                ConsoleHelper.WriteError("Could not connect to any domain controller.");
                                return null;
                            }
                        }
                    }
                }

                if (string.IsNullOrEmpty(configNC))
                {
                    Logger.LogInfo("Could not determine configuration naming context - may indicate no AD CS infrastructure");
                    ConsoleHelper.WriteInfo("No Active Directory Certificate Services infrastructure detected.");
                    return null;
                }
                
                Logger.LogInfo($"Configuration naming context found: {configNC}");
                Logger.LogInfo("Creating LDAP search entry for CA discovery");
                DirectoryEntry entry;
                if (rootDSE?.Path?.Contains("localhost") == true)
                {
                    entry = new DirectoryEntry($"LDAP://localhost/CN=Enrollment Services,CN=Public Key Services,CN=Services,{configNC}");
                }
                else if (rootDSE?.Path?.Contains("LDAP://") == true && !rootDSE.Path.Contains("localhost"))
                {
                    var domainPart = rootDSE.Path.Replace("/RootDSE", "");
                    entry = new DirectoryEntry($"{domainPart}/CN=Enrollment Services,CN=Public Key Services,CN=Services,{configNC}");
                }
                else
                {
                    entry = new DirectoryEntry($"LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,{configNC}");
                }

                Logger.LogInfo($"LDAP search base DN: {entry.Path}");

                using var searcher = new DirectorySearcher(entry)
                {
                    Filter = "(objectClass=pKIEnrollmentService)",
                    PageSize = 1000,
                    ServerTimeLimit = TimeSpan.FromSeconds(30),
                    ClientTimeout = TimeSpan.FromSeconds(30)
                };
                
                searcher.PropertiesToLoad.Add("dNSHostName");
                Logger.LogInfo("Executing LDAP search for CA enrollment services...");
                var searchTimer = System.Diagnostics.Stopwatch.StartNew();
                var results = searcher.FindAll();
                searchTimer.Stop();
                Logger.LogInfo($"LDAP search completed in {searchTimer.ElapsedMilliseconds}ms, found {results.Count} results");
                Core.PerformanceMetrics.IncrementLdapQuery(false);
                
                return results;
            }
            catch (Exception ex)
            {
                Logger.LogError("Failed to connect to AD in GetCAADObjectsWithDACLs", ex);
                ConsoleHelper.WriteError($"Failed to connect to AD: {ex.Message}");
                return null;
            }
        }

        public void FindESC6VulnerableCA()
        {
            if (!_state.IsLocalCAServer)
            {
                _state.ESC6VulnCAs.Clear();
                _state.ESC6VulnCount = 0;
                return;
            }

            ConsoleHelper.WriteInfo("Enumerating vulnerable CAs related to ESC6...");
            
            _state.ESC6VulnCAs.Clear();

            foreach (var caServer in _state.CAServerHostnames)
            {
                var vulnCA = CheckESC6OnCA(caServer);
                if (vulnCA != null)
                {
                    _state.ESC6VulnCAs.Add(vulnCA);
                }
            }

            _state.ESC6VulnCount = _state.ESC6VulnCAs.Count;
        }

        private VulnerableCA? CheckESC6OnCA(string caServer)
        {
            try
            {
                var editFlagsValue = TryGetEditFlags(caServer);
                
                if (editFlagsValue == null)
                {
                    return null;
                }

                var hasESC6Flag = (editFlagsValue.Value & Constants.EDITF_ATTRIBUTESUBJECTALTNAME2) != 0;

                if (hasESC6Flag)
                {
                    return new VulnerableCA
                    {
                        Server = caServer,
                        VulnerabilityType = "ESC6",
                        EditFlags = "EDITF_ATTRIBUTESUBJECTALTNAME2",
                        HasEditfAttributeSubjectAltName2 = true,
                        Description = "CA allows requesters to specify Subject Alternative Names in certificate requests"
                    };
                }

                return null;
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error checking ESC6 on CA {caServer}", ex);
                ConsoleHelper.WriteError($"Error checking ESC6 on CA {caServer}: {ex.Message}");
                return null;
            }
        }

        private int? TryGetEditFlags(string caServer)
        {
            var editFlags = TryGetEditFlagsMethod1(caServer);
            if (editFlags.HasValue) return editFlags;

            if (_state.IsLocalCAServer)
            {
                editFlags = TryGetEditFlagsMethod2(caServer);
                if (editFlags.HasValue) return editFlags;
            }

            editFlags = TryGetEditFlagsMethod3(caServer);
            if (editFlags.HasValue) return editFlags;

            editFlags = TryGetEditFlagsMethod4(caServer);
            if (editFlags.HasValue) return editFlags;

            return null;
        }

        private int? TryGetEditFlagsMethod1(string caServer)
        {
            try
            {
                var output = RunCertutilWithTimeout("certutil.exe", $"-config \"{caServer}\" -getreg policy\\EditFlags", 15000);
                
                if (!string.IsNullOrEmpty(output))
                {
                    return ParseEditFlagsFromOutput(output);
                }

                return null;
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error getting EditFlags from CA server '{caServer}' (Method 1)", ex);
                return null;
            }
        }

        private int? TryGetEditFlagsMethod2(string caServer)
        {
            try
            {
                var output = RunCertutilWithTimeout("certutil.exe", "-getreg policy\\EditFlags", 15000);
                
                if (!string.IsNullOrEmpty(output))
                {
                    return ParseEditFlagsFromOutput(output);
                }

                return null;
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error getting EditFlags from CA server '{caServer}' (Method 2)", ex);
                return null;
            }
        }

        private int? TryGetEditFlagsMethod3(string caServer)
        {
            try
            {
                var caNames = GetCANamesFromServer(caServer);
                
                foreach (var caName in caNames)
                {
                    var output = RunCertutilWithTimeout("certutil.exe", $"-config \"{caServer}\\{caName}\" -getreg policy\\EditFlags", 15000);
                    
                    if (!string.IsNullOrEmpty(output))
                    {
                        var result = ParseEditFlagsFromOutput(output);
                        if (result.HasValue)
                        {
                            return result;
                        }
                    }
                }

                return null;
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error getting EditFlags from CA server '{caServer}' (Method 3)", ex);
                return null;
            }
        }

        private List<string> GetCANamesFromServer(string caServer)
        {
            var caNames = new List<string>();
            
            try
            {
                var output = RunCertutilWithTimeout("certutil.exe", $"-ping \"{caServer}\"", 10000);
                
                if (!string.IsNullOrEmpty(output))
                {
                    var caNameMatch = RegexHelper.GetCaNameMatch(output);
                    if (caNameMatch.Success)
                    {
                        caNames.Add(caNameMatch.Groups[1].Value);
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.LogInfo($"Ping failed for CA server '{caServer}': {ex.Message}");
            }

            if (caNames.Count == 0)
            {
                var hostPart = caServer.Split('.')[0].ToUpper();
                caNames.Add($"{hostPart}-CA");
                caNames.Add("CA");
                caNames.Add($"{hostPart}CA");
            }

            return caNames;
        }

        private int? TryGetEditFlagsMethod4(string caServer)
        {
            try
            {
                var caNames = GetCANamesFromServer(caServer);
                
                foreach (var caName in caNames)
                {
                    var output = RunCertutilWithTimeout("certutil.exe", $"-config \"{caServer}\\{caName}\" -getconfig", 15000);
                    
                    if (!string.IsNullOrEmpty(output))
                    {
                        var editFlagsMatch = RegexHelper.GetEditFlagsMatch(output);
                        if (editFlagsMatch.Success)
                        {
                            return int.Parse(editFlagsMatch.Groups[1].Value);
                        }
                    }
                }

                return null;
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error getting EditFlags from registry configuration", ex);
                return null;
            }
        }

        private int? ParseEditFlagsFromOutput(string output)
        {
            try
            {
                var patterns = new[]
                {
                    @"EditFlags\s+REG_DWORD\s*=\s*([0-9A-Fa-f]+)\s*\((\d+)\)",
                    @"EditFlags\s+REG_DWORD\s*=\s*0x([0-9A-Fa-f]+)",
                    @"EditFlags\s+REG_DWORD\s*=\s*([0-9A-Fa-f]+)",
                    @"EditFlags\s+REG_DWORD\s*=\s*(\d+)",
                    @"policy\\EditFlags\s+REG_DWORD\s*=\s*0x([0-9A-Fa-f]+)",
                    @"policy\\EditFlags\s+REG_DWORD\s*=\s*(\d+)",
                    @"EditFlags:\s*0x([0-9A-Fa-f]+)",
                    @"EditFlags:\s*(\d+)",
                };

                foreach (var pattern in patterns)
                {
                    var regex = new Regex(pattern, RegexOptions.IgnoreCase);
                    var match = regex.Match(output);

                    if (match.Success)
                    {
                        var value = match.Groups[1].Value;
                        
                        if (pattern.Contains(@"\((\d+)\)") && match.Groups.Count > 2)
                        {
                            var hexValue = match.Groups[1].Value;
                            return Convert.ToInt32(hexValue, 16);
                        }
                        else if (pattern.Contains("0x") || value.Length > 8 || value.Any(c => "abcdefABCDEF".Contains(c)))
                        {
                            return Convert.ToInt32(value, 16);
                        }
                        else
                        {
                            return int.Parse(value);
                        }
                    }
                }

                return null;
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error parsing EditFlags from output", ex);
                return null;
            }
        }

        public void FindESC7VulnerableCA()
        {
            if (!_state.IsLocalCAServer)
            {
                _state.ESC7VulnCAPermissions.Clear();
                _state.ESC7VulnCount = 0;
                return;
            }

            ConsoleHelper.WriteInfo("Enumerating dangerous CA permissions related to ESC7...");
            
            _state.ESC7VulnCAPermissions.Clear();

            foreach (var caServer in _state.CAServerHostnames)
            {
                var vulnPermissions = CheckESC7OnCA(caServer);
                _state.ESC7VulnCAPermissions.AddRange(vulnPermissions);
            }

            _state.ESC7VulnCount = _state.ESC7VulnCAPermissions.Count;
        }

        private List<VulnerableCAPermissions> CheckESC7OnCA(string caServer)
        {
            var vulnerablePermissions = new List<VulnerableCAPermissions>();

            try
            {
                var caAclInfo = TryGetCAAcl(caServer);
                if (caAclInfo != null && caAclInfo.Count > 0)
                {
                    foreach (var aclEntry in caAclInfo)
                    {
                        if (IsVulnerableCAPermission(aclEntry))
                        {
                            vulnerablePermissions.Add(aclEntry);
                        }
                    }
                }

            }
            catch (Exception ex)
            {
                Logger.LogError($"Error checking ESC7 on CA {caServer}", ex);
                ConsoleHelper.WriteError($"Error checking ESC7 on CA {caServer}: {ex.Message}");
            }

            return vulnerablePermissions;
        }

        private List<VulnerableCAPermissions> TryGetCAAcl(string caServer)
        {
            var permissions = new List<VulnerableCAPermissions>();

            permissions.AddRange(TryGetCAPermissionsFromCertutil(caServer));
            if (permissions.Count > 0)
            {
                return permissions;
            }

            permissions.AddRange(TryGetCAPermissionsFromRegistry(caServer));
            if (permissions.Count > 0)
            {
                return permissions;
            }

            return permissions;
        }

        private List<VulnerableCAPermissions> TryGetCAPermissionsFromRegistry(string caServer)
        {
            var permissions = new List<VulnerableCAPermissions>();

            try
            {
                if (!_state.IsLocalCAServer)
                    return permissions;

                var caConfigPath = @"SYSTEM\CurrentControlSet\Services\CertSvc\Configuration";
                
                using var configKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(caConfigPath);
                if (configKey == null) return permissions;

                var caNames = configKey.GetSubKeyNames();
                foreach (var caName in caNames)
                {
                    using var caKey = configKey.OpenSubKey(caName);
                    if (caKey == null) continue;

                    var securityDescriptor = caKey.GetValue("Security") as byte[];
                    if (securityDescriptor != null && securityDescriptor.Length > 0)
                    {
                        permissions.AddRange(ParseSecurityDescriptor(securityDescriptor, caServer));
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.LogError("Registry access failed (expected if not local CA admin)", ex);
                ConsoleHelper.WriteInfo($"Registry access failed (expected if not local CA admin): {ex.Message}");
            }

            return permissions;
        }

        private List<VulnerableCAPermissions> TryGetCAPermissionsFromCertutil(string caServer)
        {
            var permissions = new List<VulnerableCAPermissions>();

            try
            {
                var output = RunCertutilCommand("certutil -v -getreg ca\\Security");
                if (!string.IsNullOrEmpty(output))
                {
                    permissions.AddRange(ParseCertutilSecurityOutput(output, caServer));
                }
            }
            catch (Exception ex)
            {
                Logger.LogInfo($"Failed to get CA security descriptor via certutil: {ex.Message}");
            }

            return permissions;
        }

        private List<VulnerableCAPermissions> ParseSecurityDescriptor(byte[] securityDescriptor, string caServer)
        {
            var permissions = new List<VulnerableCAPermissions>();
            
            try
            {
                var sdString = System.Text.Encoding.ASCII.GetString(securityDescriptor);
                
                if (sdString.Contains("S-1-1-0") ||
                    sdString.Contains("S-1-5-11") ||
                    sdString.Contains("S-1-5-32-545"))
                {
                    permissions.Add(new VulnerableCAPermissions
                    {
                        Server = caServer,
                        VulnerabilityType = "ESC7",
                        Principal = "Low-privileged account (detected via registry)",
                        Permission = "ManageCA or ManageCertificates",
                        Description = "Non-privileged account has dangerous CA permissions (detected via security descriptor)",
                        IsPrivilegedAccount = false
                    });
                }
            }
            catch (Exception ex)
            {
                Logger.LogError("Security descriptor parsing failed", ex);
                ConsoleHelper.WriteInfo($"Security descriptor parsing failed: {ex.Message}");
            }
            
            return permissions;
        }

        private string RunCertutilCommand(string command)
        {
            try
            {
                var parts = command.Split(' ', 2);
                var fileName = parts[0];
                var arguments = parts.Length > 1 ? parts[1] : "";
                
                return RunCertutilWithTimeout(fileName, arguments, 30000);
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error running certutil command", ex);
                return string.Empty;
            }
        }

        private string RunCertutilWithTimeout(string fileName, string arguments, int timeoutMs = 30000)
        {
            try
            {
                var processInfo = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(processInfo);
                if (process == null) return string.Empty;

                var output = process.StandardOutput.ReadToEnd();
                
                var completed = process.WaitForExit(timeoutMs);
                if (!completed)
                {
                    Logger.LogWarning($"Certutil process timed out after {timeoutMs}ms: {fileName} {arguments}");
                    try
                    {
                        process.Kill();
                    }
                    catch (Exception killEx)
                    {
                        Logger.LogError($"Failed to kill hung certutil process", killEx);
                    }
                    return string.Empty;
                }

                return process.ExitCode == 0 ? output : string.Empty;
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error running certutil process", ex);
                return string.Empty;
            }
        }

        private List<VulnerableCAPermissions> ParseCertutilSecurityOutput(string output, string caServer)
        {
            var permissions = new List<VulnerableCAPermissions>();
            var lines = output.Split('\n');

            try
            {
                foreach (var line in lines)
                {
                    var cleanLine = line.Trim();            
                    string permission = "";
                    string principal = "";
                    bool foundDangerousPermission = false;
                    
                    if (cleanLine.Contains("CA Administrator") && cleanLine.Contains("Certificate Manager"))
                    {
                        foundDangerousPermission = true;
                        permission = "ManageCA + ManageCertificates";
                        
                        var certManagerIndex = cleanLine.IndexOf("Certificate Manager");
                        if (certManagerIndex >= 0)
                        {
                            principal = cleanLine.Substring(certManagerIndex + "Certificate Manager".Length).Trim();
                        }
                    }
                    else if (cleanLine.Contains("CA Administrator"))
                    {
                        foundDangerousPermission = true;
                        permission = "ManageCA";
                        
                        var caAdminIndex = cleanLine.IndexOf("CA Administrator");
                        if (caAdminIndex >= 0)
                        {
                            var afterCaAdmin = cleanLine.Substring(caAdminIndex + "CA Administrator".Length).Trim();
                            var parts = afterCaAdmin.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                            if (parts.Length > 0)
                            {
                                principal = parts[parts.Length - 1];
                            }
                        }
                    }
                    else if (cleanLine.Contains("Certificate Manager"))
                    {
                        foundDangerousPermission = true;
                        permission = "ManageCertificates";
                        
                        var certManagerIndex = cleanLine.IndexOf("Certificate Manager");
                        if (certManagerIndex >= 0)
                        {
                            principal = cleanLine.Substring(certManagerIndex + "Certificate Manager".Length).Trim();
                        }
                    }
                    
                    if (foundDangerousPermission)
                    {
                        if (!string.IsNullOrEmpty(principal))
                        {
                            var accountName = ExtractUsernameFromPrincipal(principal);
                            
                            if (ShouldExcludeAccount(accountName, principal))
                            {
                                Logger.LogInfo($"Account '{principal}' excluded from ESC7 reporting (machine account or CA server)");
                                continue;
                            }
                            
                            var isPrivileged = IsPrivilegedAccount(principal);
                            
                            if (!isPrivileged)
                            {
                                permissions.Add(new VulnerableCAPermissions
                                {
                                    Server = caServer,
                                    VulnerabilityType = "ESC7",
                                    Principal = principal,
                                    Permission = permission,
                                    Description = GetPermissionDescription(permission),
                                    IsPrivilegedAccount = false
                                });
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.LogError("ESC7: Failed to parse certutil security output", ex);
                ConsoleHelper.WriteError($"ESC7: Failed to parse certutil security output: {ex.Message}");
            }

            return permissions;
        }







        private string GetPermissionDescription(string permission)
        {
            return permission switch
            {
                "ManageCA" => "Principal can manage CA configuration (including enabling ESC6 via EDITF_ATTRIBUTESUBJECTALTNAME2)",
                "ManageCertificates" => "Principal can approve pending certificate requests (bypassing Manager Approval protection)",
                "ManageCA + ManageCertificates" => "Principal has full CA Administrator privileges (ManageCA + ManageCertificates)",
                _ => "Dangerous CA permission detected"
            };
        }

        private bool IsVulnerableCAPermission(VulnerableCAPermissions permission)
        {
            return !permission.IsPrivilegedAccount && 
                   (permission.Permission.Contains("ManageCA") || permission.Permission.Contains("ManageCertificates"));
        }

        /// <summary>
        /// Checks if an account should be excluded from vulnerability reporting
        /// Excludes: machine accounts ($), CA server accounts, and accounts in ExcludedAccounts list
        /// </summary>
        private bool ShouldExcludeAccount(string accountName, string? fullAccountName = null)
        {
            if (string.IsNullOrEmpty(accountName))
                return false;

            var normalizedAccount = accountName.ToLower().Trim();
            var fullName = fullAccountName ?? accountName;
            var normalizedFullName = fullName.ToLower().Trim();

            if (fullName.EndsWith("$", StringComparison.OrdinalIgnoreCase))
            {
                Logger.LogInfo($"Account '{fullName}' excluded: machine account (ends with $)");
                return true;
            }

            foreach (var caServer in _state.CAServerHostnames)
            {
                if (string.IsNullOrEmpty(caServer))
                    continue;

                var caHostname = caServer.Split('.')[0].ToLower();
                var caMachineAccount = $"{caHostname}$";

                if (normalizedFullName.EndsWith(caMachineAccount, StringComparison.OrdinalIgnoreCase) ||
                    normalizedAccount.Equals(caHostname, StringComparison.OrdinalIgnoreCase))
                {
                    Logger.LogInfo($"Account '{fullName}' excluded: CA server machine account ({caServer})");
                    return true;
                }
            }

            foreach (var excludedGroup in Constants.ExcludedGroups)
            {
                if (string.IsNullOrEmpty(excludedGroup))
                    continue;

                var normalizedExcluded = excludedGroup.ToLower().Trim();
                
                if (normalizedFullName.Equals(normalizedExcluded, StringComparison.OrdinalIgnoreCase) ||
                    normalizedAccount.Equals(normalizedExcluded, StringComparison.OrdinalIgnoreCase) ||
                    normalizedFullName.EndsWith($"\\{normalizedExcluded}", StringComparison.OrdinalIgnoreCase))
                {
                    Logger.LogInfo($"Account '{fullName}' excluded: in ExcludedGroups list");
                    return true;
                }
            }

            foreach (var excludedUser in Constants.ExcludedUsers)
            {
                if (string.IsNullOrEmpty(excludedUser))
                    continue;

                var normalizedExcluded = excludedUser.ToLower().Trim();
                
                if (normalizedFullName.Equals(normalizedExcluded, StringComparison.OrdinalIgnoreCase) ||
                    normalizedAccount.Equals(normalizedExcluded, StringComparison.OrdinalIgnoreCase) ||
                    normalizedFullName.EndsWith($"\\{normalizedExcluded}", StringComparison.OrdinalIgnoreCase))
                {
                    Logger.LogInfo($"Account '{fullName}' excluded: in ExcludedUsers list");
                    return true;
                }
            }

            return false;
        }

        private bool IsPrivilegedAccount(string principal)
        {
            if (string.IsNullOrEmpty(principal))
                return false;

            try
            {
                var accountName = ExtractUsernameFromPrincipal(principal);
                if (string.IsNullOrEmpty(accountName))
                {
                    return IsPrivilegedByName(principal);
                }

                if (ShouldExcludeAccount(accountName, principal))
                {
                    return true;
                }

                if (IsWellKnownPrivilegedGroup(accountName))
                {
                    return true;
                }

                AccountType accountType = AdHelper.GetAccountType(accountName);
                
                if (accountType == AccountType.Group)
                {
                    var isPrivileged = IsPrivilegedGroup(accountName);
                    return isPrivileged;
                }

                if (accountType == AccountType.User)
                {
                    var userGroups = GetUserGroupMemberships(accountName);
                    
                    foreach (var group in userGroups)
                    {
                        if (IsPrivilegedGroup(group))
                        {
                            return true;
                        }
                    }
                }

                return false;
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error checking if principal is privileged", ex);
                return IsPrivilegedByName(principal);
            }
        }

        private string ExtractUsernameFromPrincipal(string principal)
        {
            try
            {
                if (principal.Contains("\\"))
                {
                    var parts = principal.Split('\\');
                    return parts.Length > 1 ? parts[1].Trim() : principal.Trim();
                }
                else if (principal.Contains("@"))
                {
                    var parts = principal.Split('@');
                    return parts.Length > 0 ? parts[0].Trim() : principal.Trim();
                }
                else
                {
                    return principal.Trim();
                }
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error extracting username from principal '{principal}'", ex);
                return principal?.Trim() ?? string.Empty;
            }
        }

        private List<string> GetUserGroupMemberships(string username)
        {
            var groups = new List<string>();
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            Logger.LogInfo($"Getting group memberships for user '{username}'");

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
                        Logger.LogInfo("User group lookup LDAP connection method 1: SUCCESS");
                    }
                }
                    catch (Exception ex)
                    {
                        Logger.LogError("User group lookup LDAP connection method 1 failed", ex);
                        try
                        {
                            var domainEntry = new DirectoryEntry("LDAP://localhost");
                        searcher = new DirectorySearcher(domainEntry);
                        Logger.LogInfo("User group lookup LDAP connection method 2: SUCCESS");
                    }
                        catch (Exception ex2)
                        {
                            Logger.LogError("User group lookup LDAP connection method 2 failed", ex2);
                            try
                            {
                                var machineName = Environment.MachineName;
                            var machineEntry = new DirectoryEntry($"LDAP://{machineName}");
                            var machineSearcher = new DirectorySearcher(machineEntry);
                            machineSearcher.PropertiesToLoad.Add("defaultNamingContext");
                            var machineResult = machineSearcher.FindOne();
                            if (machineResult?.Properties["defaultNamingContext"].Count > 0)
                            {
                                var domainNC = machineResult.Properties["defaultNamingContext"][0].ToString();
                                var domainEntry = new DirectoryEntry($"LDAP://{machineName}/{domainNC}");
                                searcher = new DirectorySearcher(domainEntry);
                                Logger.LogInfo("User group lookup LDAP connection method 3: SUCCESS");
                            }
                        }
                            catch (Exception ex3)
                            {
                                Logger.LogError("User group lookup LDAP connection method 3 failed", ex3);
                                try
                                {
                        searcher = new DirectorySearcher();
                                Logger.LogInfo("User group lookup LDAP connection method 4: SUCCESS");
                            }
                            catch (Exception ex4)
                            {
                                Logger.LogError("All user group lookup LDAP connection methods failed", ex4);
                                return groups; // Return empty list
                            }
                        }
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
                        searcher.ServerTimeLimit = TimeSpan.FromSeconds(30);
                        searcher.ClientTimeout = TimeSpan.FromSeconds(30);

                        var result = searcher.FindOne();
                        if (result?.Properties["memberOf"] != null)
                        {
                            foreach (string groupDN in result.Properties["memberOf"])
                            {
                                var groupName = ExtractGroupNameFromDN(groupDN);
                                if (!string.IsNullOrEmpty(groupName))
                                {
                                    groups.Add(groupName);
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
                    }
                }
                else
                {
                }
            }
            catch (Exception ex)
            {
                Logger.LogError($"Failed to get group memberships for user '{username}'", ex);
            }

            stopwatch.Stop();
            Logger.LogInfo($"Group memberships for user '{username}' retrieved in {stopwatch.ElapsedMilliseconds}ms, found {groups.Count} groups");
            Core.PerformanceMetrics.IncrementGroupMembershipQuery(false);
            return groups;
        }

        private string ExtractGroupNameFromDN(string distinguishedName)
        {
            try
            {
                if (distinguishedName.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                {
                    var cnPart = distinguishedName.Substring(3); // Remove "CN="
                    var commaIndex = cnPart.IndexOf(',');
                    return commaIndex > 0 ? cnPart.Substring(0, commaIndex) : cnPart;
                }
                return string.Empty;
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error extracting group name from DN '{distinguishedName}'", ex);
                return string.Empty;
            }
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

        private bool IsPrivilegedGroup(string groupName)
        {
            if (string.IsNullOrEmpty(groupName))
                return false;

            var normalizedGroup = groupName.ToLower().Trim();

            foreach (var excludedGroup in Constants.ExcludedGroups)
            {
                if (string.IsNullOrEmpty(excludedGroup))
                    continue;
                
                var normalizedExcluded = excludedGroup.ToLower().Trim();
                if (normalizedGroup.Equals(normalizedExcluded, StringComparison.OrdinalIgnoreCase) ||
                    normalizedGroup.EndsWith($"\\{normalizedExcluded}", StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            foreach (var excludedUser in Constants.ExcludedUsers)
            {
                if (string.IsNullOrEmpty(excludedUser))
                    continue;
                
                var normalizedExcluded = excludedUser.ToLower().Trim();
                if (normalizedGroup.Equals(normalizedExcluded, StringComparison.OrdinalIgnoreCase) ||
                    normalizedGroup.EndsWith($"\\{normalizedExcluded}", StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            foreach (var group in Constants.ExcludedGroups)
            {
                if (normalizedGroup.Equals(group.ToLower(), StringComparison.OrdinalIgnoreCase))
                    return true;
            }


            return false;
        }

        private bool IsWellKnownPrivilegedGroup(string accountName)
        {
            if (string.IsNullOrEmpty(accountName))
                return false;

            var normalizedName = accountName.ToLower().Trim();
            
            foreach (var excludedGroup in Constants.ExcludedGroups)
            {
                if (string.IsNullOrEmpty(excludedGroup))
                    continue;
                
                var normalizedExcluded = excludedGroup.ToLower().Trim();
                if (normalizedName.Equals(normalizedExcluded, StringComparison.OrdinalIgnoreCase) ||
                    normalizedName.EndsWith($"\\{normalizedExcluded}", StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }


        private bool IsPrivilegedByName(string principal)
        {
            var normalizedPrincipal = principal.ToLower().Trim();

            foreach (var group in Constants.ExcludedGroups)
            {
                if (normalizedPrincipal.Contains(group.ToLower()))
                    return true;
            }

            foreach (var sid in Constants.ExcludedGroups)
            {
                if (normalizedPrincipal.Contains(sid.ToLower()))
                    return true;
            }


            return false;
        }

        private string ResolveCAServerIP(string hostname)
        {
            try
            {
                var hostEntry = System.Net.Dns.GetHostEntry(hostname);
                var ipAddress = hostEntry.AddressList
                    .FirstOrDefault(ip => ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
                
                return ipAddress?.ToString() ?? string.Empty;
            }
            catch (Exception ex)
            {
                Logger.LogInfo($"Could not resolve IP for CA server '{hostname}': {ex.Message}");
                return string.Empty;
            }
        }

        public void Dispose()
        {
            _httpClient?.Dispose();
        }
    }
} 