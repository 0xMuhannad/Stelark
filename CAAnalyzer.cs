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

namespace Stelark
{
    public class CAAnalyzer : IDisposable
    {
        private readonly GlobalState _state;
        private readonly HttpClient _httpClient;

        public CAAnalyzer(GlobalState state)
        {
            _state = state;
            _httpClient = new HttpClient();
            _httpClient.Timeout = TimeSpan.FromSeconds(10);
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
                    Logger.LogInfo("Could not determine configuration naming context - may indicate no ADCS infrastructure");
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
                    var caNameMatch = Regex.Match(output, @"Server\s+""([^""]+)""", RegexOptions.IgnoreCase);
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
                        var editFlagsMatch = Regex.Match(output, @"EditFlags.*?(\d+)", RegexOptions.IgnoreCase);
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
                // Method 1: Try using certutil to get CA ACL information
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

            // Method 1: Try the working certutil command (as shown in manual test)
            permissions.AddRange(TryGetCAPermissionsFromCertutil(caServer));
            if (permissions.Count > 0)
            {
                return permissions;
            }

            // Method 2: Try registry access (fallback for local CA)
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
                // Only attempt registry access for local CA server
                if (!_state.IsLocalCAServer)
                    return permissions;

                // Try to read CA security settings from registry
                // HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CAName>\Security
                var caConfigPath = @"SYSTEM\CurrentControlSet\Services\CertSvc\Configuration";
                
                using var configKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(caConfigPath);
                if (configKey == null) return permissions;

                // Get CA name for registry path
                var caNames = configKey.GetSubKeyNames();
                foreach (var caName in caNames)
                {
                    using var caKey = configKey.OpenSubKey(caName);
                    if (caKey == null) continue;

                    var securityDescriptor = caKey.GetValue("Security") as byte[];
                    if (securityDescriptor != null && securityDescriptor.Length > 0)
                    {
                        // Parse the security descriptor for ManageCA and ManageCertificates permissions
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
                // Use the exact command that works (as demonstrated by user)
                var output = RunCertutilCommand("certutil -v -getreg ca\\Security");
                if (!string.IsNullOrEmpty(output))
                {
                    permissions.AddRange(ParseCertutilSecurityOutput(output, caServer));
                }
            }
            catch (Exception ex)
            {
                // Silent failure - expected for some CA configurations
                Logger.LogInfo($"Failed to get CA security descriptor via certutil: {ex.Message}");
            }

            return permissions;
        }

        private List<VulnerableCAPermissions> ParseSecurityDescriptor(byte[] securityDescriptor, string caServer)
        {
            var permissions = new List<VulnerableCAPermissions>();
            
            try
            {
                // Simplified security descriptor parsing
                // In practice, this would require full SD parsing using Windows APIs
                // For now, use basic heuristics to detect common misconfigurations
                
                // Convert byte array to string to look for patterns (simplified approach)
                var sdString = System.Text.Encoding.ASCII.GetString(securityDescriptor);
                
                // Look for non-privileged SIDs with dangerous permissions
                // This is a simplified detection - real implementation would parse ACEs properly
                if (sdString.Contains("S-1-1-0") || // Everyone
                    sdString.Contains("S-1-5-11") || // Authenticated Users  
                    sdString.Contains("S-1-5-32-545")) // Users
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
                    
                    // More flexible parsing - check if line contains the dangerous permissions
                    if (cleanLine.Contains("CA Administrator") && cleanLine.Contains("Certificate Manager"))
                    {
                        // User has BOTH CA Administrator AND Certificate Manager permissions
                        foundDangerousPermission = true;
                        permission = "ManageCA + ManageCertificates";
                        
                        // Extract principal - get everything after "Certificate Manager"
                        var certManagerIndex = cleanLine.IndexOf("Certificate Manager");
                        if (certManagerIndex >= 0)
                        {
                            principal = cleanLine.Substring(certManagerIndex + "Certificate Manager".Length).Trim();
                        }
                    }
                    else if (cleanLine.Contains("CA Administrator"))
                    {
                        // User has CA Administrator permission (ManageCA)
                        foundDangerousPermission = true;
                        permission = "ManageCA";
                        
                        // Extract principal - get everything after "CA Administrator"
                        var caAdminIndex = cleanLine.IndexOf("CA Administrator");
                        if (caAdminIndex >= 0)
                        {
                            var afterCaAdmin = cleanLine.Substring(caAdminIndex + "CA Administrator".Length).Trim();
                            // Skip any intermediate words like "Enroll" and get the principal
                            var parts = afterCaAdmin.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                            if (parts.Length > 0)
                            {
                                // Get the last part which should be the principal (DOMAIN\user)
                                principal = parts[parts.Length - 1];
                            }
                        }
                    }
                    else if (cleanLine.Contains("Certificate Manager"))
                    {
                        // User has standalone Certificate Manager permission (ManageCertificates)
                        foundDangerousPermission = true;
                        permission = "ManageCertificates";
                        
                        // Extract principal - get everything after "Certificate Manager"
                        var certManagerIndex = cleanLine.IndexOf("Certificate Manager");
                        if (certManagerIndex >= 0)
                        {
                            principal = cleanLine.Substring(certManagerIndex + "Certificate Manager".Length).Trim();
                        }
                    }
                    
                    if (foundDangerousPermission)
                    {
                        // Check if this principal is non-privileged
                        if (!string.IsNullOrEmpty(principal))
                        {
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
                // Parsing failed - return empty list
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
            // Only report if it's a non-privileged account with dangerous permissions
            return !permission.IsPrivilegedAccount && 
                   (permission.Permission.Contains("ManageCA") || permission.Permission.Contains("ManageCertificates"));
        }

        private bool IsPrivilegedAccount(string principal)
        {
            if (string.IsNullOrEmpty(principal))
                return false;

            try
            {
                // Step 1: Extract the account name from DOMAIN\account format
                var accountName = ExtractUsernameFromPrincipal(principal);
                if (string.IsNullOrEmpty(accountName))
                {
                    // Fallback to old name-based detection for malformed principals
                    return IsPrivilegedByName(principal);
                }

                // Step 2: Check if this is a well-known privileged group
                if (IsWellKnownPrivilegedGroup(accountName))
                {
                    return true;
                }

                // Step 3: Check if this looks like a group name (vs individual user)
                if (IsLikelyGroupName(accountName))
                {
                    // It's likely a group - check if it's privileged or not
                    var isPrivileged = IsPrivilegedGroup(accountName);
                    
                    // For groups: privileged = expected (not vulnerable), non-privileged = vulnerable
                    return isPrivileged;
                }

                // Step 4: It's likely a user - query AD for their group memberships
                var userGroups = GetUserGroupMemberships(accountName);
                
                // Step 5: Check if ANY of their groups are privileged
                foreach (var group in userGroups)
                {
                    if (IsPrivilegedGroup(group))
                    {
                        return true;
                    }
                }

                return false;
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error checking if principal is privileged", ex);
                // Fallback to name-based detection if all else fails
                return IsPrivilegedByName(principal);
            }
        }

        private string ExtractUsernameFromPrincipal(string principal)
        {
            try
            {
                // Handle formats: DOMAIN\username, username@domain.com, or just username
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
                // Use optimized LDAP connection order (same as other fixes)
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
                        Logger.LogInfo("User group lookup LDAP connection method 1: SUCCESS");
                    }
                }
                catch (Exception ex)
                {
                    Logger.LogError("User group lookup LDAP connection method 1 failed", ex);
                    try
                    {
                        // Method 2: localhost
                        var domainEntry = new DirectoryEntry("LDAP://localhost");
                        searcher = new DirectorySearcher(domainEntry);
                        Logger.LogInfo("User group lookup LDAP connection method 2: SUCCESS");
                    }
                    catch (Exception ex2)
                    {
                        Logger.LogError("User group lookup LDAP connection method 2 failed", ex2);
                        try
                        {
                            // Method 3: Machine's domain
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
                                // Method 4: Default DirectorySearcher (fallback)
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
                            var primaryGroupName = GetUserPrimaryGroup(result);
                            if (!string.IsNullOrEmpty(primaryGroupName) && !groups.Contains(primaryGroupName))
                            {
                                groups.Add(primaryGroupName);
                            }
                        }
                        else
                        {
                            // If no result found, add Domain Users as default
                            groups.Add("Domain Users");
                        }
                    }
                }
                else
                {
                    // If searcher couldn't be created, add default group
                    groups.Add("Domain Users");
                }
            }
            catch (Exception ex)
            {
                Logger.LogError($"Failed to get group memberships for user '{username}'", ex);
                // Add Domain Users as default assumption if query fails
                groups.Add("Domain Users");
            }

            stopwatch.Stop();
            Logger.LogInfo($"Group memberships for user '{username}' retrieved in {stopwatch.ElapsedMilliseconds}ms, found {groups.Count} groups");
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

        private string GetUserPrimaryGroup(SearchResult? result)
        {
            try
            {
                if (result?.Properties["primaryGroupID"] != null)
                {
                    var primaryGroupID = result.Properties["primaryGroupID"][0];
                    
                    if (primaryGroupID.ToString() == "513")
                    {
                        return "Domain Users";
                    }
                    
                    switch (primaryGroupID.ToString())
                    {
                        case "512": return "Domain Admins";
                        case "513": return "Domain Users";
                        case "514": return "Domain Guests";
                        case "515": return "Domain Computers";
                        case "516": return "Domain Controllers";
                        default: return "Domain Users"; // Default fallback
                    }
                }
                
                return "Domain Users"; // Default assumption
            }
            catch (Exception ex)
            {
                Logger.LogError($"Error getting user primary group", ex);
                return "Domain Users"; // Default assumption
            }
        }

        private bool IsPrivilegedGroup(string groupName)
        {
            if (string.IsNullOrEmpty(groupName))
                return false;

            var normalizedGroup = groupName.ToLower().Trim();

            // Check CA-specific privileged groups
            foreach (var group in Constants.CAPrivilegedGroups)
            {
                if (normalizedGroup.Equals(group.ToLower(), StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            // Check general privileged groups
            foreach (var group in Constants.PrivilegedGroups)
            {
                if (normalizedGroup.Equals(group.ToLower(), StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            // Check for privileged keywords in group names (enhanced detection)
            var privilegedKeywords = new[] { 
                "admin", "administrator", "operator", "backup", "schema", "enterprise", 
                "certificate", "cert", "security", "exchange", "dns", "manager", 
                "supervisor", "privilege", "power", "service", "system", "infrastructure",
                "it", "tech", "root", "super", "elevated", "senior"
            };

            foreach (var keyword in privilegedKeywords)
            {
                if (normalizedGroup.Contains(keyword))
                    return true;
            }

            // Additional check: any group with "admin" in any form should be privileged
            if (normalizedGroup.Contains("admin"))
                return true;

            return false;
        }

        private bool IsWellKnownPrivilegedGroup(string accountName)
        {
            var normalizedName = accountName.ToLower().Trim();
            
            // Well-known privileged groups that should always be considered privileged
            var wellKnownGroups = new[]
            {
                "domain admins", "enterprise admins", "administrators", "schema admins",
                "account operators", "server operators", "backup operators", "print operators",
                "cert publishers", "group policy creator owners", "dns admins", 
                "exchange admins", "organization management", "security admins", 
                "security operators", "certificate managers", "ca administrators"
            };

            return wellKnownGroups.Contains(normalizedName);
        }

        private bool IsLikelyGroupName(string accountName)
        {
            var normalizedName = accountName.ToLower().Trim();
            
            // Heuristics to identify group names vs individual usernames
            var groupIndicators = new[]
            {
                // Standard group words
                "admins", "administrators", "operators", "users", "managers", 
                "publishers", "creators", "owners", "security", "backup",
                "account", "server", "print", "dns", "exchange", "organization",
                
                // Custom group patterns  
                "team", "group", "dept", "department", "service", "app", 
                "application", "dev", "developer", "test", "testing", 
                "prod", "production", "support", "helpdesk", "it",
                "finance", "hr", "sales", "marketing", "guests"
            };

            // If it contains typical group words, likely a group
            foreach (var indicator in groupIndicators)
            {
                if (normalizedName.Contains(indicator))
                    return true;
            }

            // If it looks like a person's name (firstname.lastname), likely a user
            if (Regex.IsMatch(normalizedName, @"^[a-z]+\.[a-z]+$"))
                return false;

            // If it contains spaces, more likely to be a group name
            if (normalizedName.Contains(" "))
                return true;

            // If it's all caps, might be a service/group name
            if (accountName == accountName.ToUpper() && accountName.Length > 3)
                return true;

            return false; // Default to treating as user
        }

        private bool IsPrivilegedByName(string principal)
        {
            // Original name-based detection as fallback
            var normalizedPrincipal = principal.ToLower().Trim();

            // Check CA-specific privileged groups
            foreach (var group in Constants.CAPrivilegedGroups)
            {
                if (normalizedPrincipal.Contains(group.ToLower()))
                    return true;
            }

            // Check general privileged groups
            foreach (var group in Constants.PrivilegedGroups)
            {
                if (normalizedPrincipal.Contains(group.ToLower()))
                    return true;
            }

            // Check privileged SIDs
            foreach (var sid in Constants.PrivilegedSIDs)
            {
                if (normalizedPrincipal.Contains(sid.ToLower()))
                    return true;
            }

            // Check for built-in privileged accounts (enhanced detection)
            var privilegedKeywords = new[] { 
                "administrator", "admin", "krbtgt", "enterprise", "schema", 
                "cert publisher", "ca administrator", "manager", "supervisor", 
                "privilege", "power", "service", "system", "infrastructure",
                "operator", "backup", "security", "exchange", "dns"
            };

            foreach (var keyword in privilegedKeywords)
            {
                if (normalizedPrincipal.Contains(keyword))
                    return true;
            }

            // Ensure any group/user with "admin" anywhere in the name is privileged
            if (normalizedPrincipal.Contains("admin"))
                return true;

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