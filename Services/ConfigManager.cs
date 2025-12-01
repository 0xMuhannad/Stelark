using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using Stelark.Core;
using Stelark.Helpers;
using Stelark.Models;

namespace Stelark.Services
{
    public static class ConfigManager
    {
        private static StelarkConfig? _config;
        private static readonly object _lock = new object();

        private static bool _configWasMissing = false;
        private static string? _missingConfigPath = null;

        private static string? _configFilePath = null;
        private static bool _configFileExists = false;
        private static bool _configValidated = false;
        private static List<string> _rejectedItems = new List<string>();
        private static string? _jsonError = null;

        public static StelarkConfig LoadConfig(string? configPath = null)
        {
            if (_config != null)
                return _config;

            lock (_lock)
            {
                if (_config != null)
                    return _config;

                if (string.IsNullOrEmpty(configPath))
                {
                    configPath = Path.Combine(AppContext.BaseDirectory, "Stelark.config");
                }

                _configFilePath = Path.GetFullPath(configPath);
                _configFileExists = File.Exists(_configFilePath);

                if (!_configFileExists)
                {
                    _configWasMissing = true;
                    _missingConfigPath = _configFilePath;
                    Logger.LogWarning($"Config file not found at {_configFilePath}, using default values");
                    _config = CreateDefaultConfig();
                    SaveConfig(_config, _configFilePath);
                    _configValidated = true;
                    return _config;
                }

                var jsonContent = File.ReadAllText(_configFilePath);
                var fixedJson = FixSingleBackslashInJson(jsonContent);
                var wasJsonFixed = fixedJson != jsonContent;
                
                try
                {
                    var options = new JsonSerializerOptions
                    {
                        ReadCommentHandling = JsonCommentHandling.Skip,
                        AllowTrailingCommas = true
                    };
                    
                    StelarkConfig? rawConfig = null;
                    try
                    {
                        rawConfig = JsonSerializer.Deserialize<StelarkConfig>(fixedJson, options);
                    }
                    catch (JsonException)
                    {
                        if (wasJsonFixed)
                        {
                            Logger.LogWarning("JSON had single backslash issues that were auto-fixed, but JSON still has other errors");
                        }
                        throw;
                    }
                    
                    if (rawConfig == null)
                    {
                        _jsonError = "Config file is empty or invalid";
                        Logger.LogError(_jsonError);
                        _config = CreateDefaultConfig();
                        _configValidated = false;
                        return _config;
                    }

                    if (wasJsonFixed)
                    {
                        Logger.LogInfo("Auto-fixed single backslash issues in JSON config file");
                    }

                    _config = ValidateAndFixConfig(rawConfig, fixedJson);
                    _configValidated = true;
                }
                catch (JsonException jsonEx)
                {
                    var lineNumber = GetLineNumberFromJsonError(jsonContent, jsonEx);
                    var problematicValue = ExtractProblematicValueFromJson(jsonContent, jsonEx);
                    var index = ExtractIndexFromPath(jsonEx.Path);
                    var arrayName = jsonEx.Path?.Contains("ExcludedUsers") == true ? "ExcludedUsers" : 
                                   jsonEx.Path?.Contains("ExcludedGroups") == true ? "ExcludedGroups" : null;
                    
                    if (!string.IsNullOrEmpty(problematicValue) && !string.IsNullOrEmpty(arrayName))
                    {
                        var errorMsg = jsonEx.Message.ToLower();
                        var isSlashError = errorMsg.Contains("escapable") || errorMsg.Contains("backslash") || 
                                          problematicValue.Contains("\\") || problematicValue.Contains("\\\\");
                        
                        if (isSlashError)
                        {
                            _jsonError = $"{arrayName}[{index}]: '{problematicValue}' - Invalid JSON format (use exactly 2 backslashes: 'DOMAIN\\\\USERNAME')";
                        }
                        else
                        {
                            _jsonError = $"{arrayName}[{index}]: '{problematicValue}' - {jsonEx.Message}";
                        }
                        _rejectedItems = new List<string> { _jsonError };
                    }
                    else
                    {
                        _jsonError = $"JSON syntax error at line {lineNumber}: {jsonEx.Message}";
                    }
                    
                    Logger.LogError(_jsonError, jsonEx);
                    
                    var partialConfig = TryExtractPartialConfig(jsonContent, new List<string>());
                    if (partialConfig != null)
                    {
                        _config = ValidateAndFixConfig(partialConfig, jsonContent);
                    }
                    else
                    {
                        _config = CreateDefaultConfig();
                    }
                    _configValidated = false;
                }
                catch (Exception ex)
                {
                    _jsonError = $"Failed to load config file: {ex.Message}";
                    Logger.LogError(_jsonError, ex);
                    _config = CreateDefaultConfig();
                    _configValidated = false;
                }

                return _config;
            }
        }

        private static StelarkConfig ValidateAndFixConfig(StelarkConfig rawConfig, string jsonContent)
        {
            var validGroups = new List<string>();
            var validUsers = new List<string>();
            var fixedItems = new List<string>();
            _rejectedItems = new List<string>();

            if (rawConfig.ExcludedGroups != null)
            {
                for (int i = 0; i < rawConfig.ExcludedGroups.Count; i++)
                {
                    var group = rawConfig.ExcludedGroups[i];
                    if (string.IsNullOrWhiteSpace(group))
                    {
                        _rejectedItems.Add($"ExcludedGroups[{i}]: Empty entry - not excluded");
                        continue;
                    }

                    try
                    {
                        var result = ValidateAndFixAccount(group, jsonContent);
                        if (result.IsValid)
                        {
                            validGroups.Add(result.FixedValue ?? group);
                            if (result.WasFixed)
                            {
                                fixedItems.Add($"ExcludedGroups[{i}]: '{group}' -> '{result.FixedValue}' (auto-fixed single backslash)");
                            }
                        }
                        else
                        {
                            _rejectedItems.Add($"ExcludedGroups[{i}]: '{group}' - {result.ErrorReason}");
                        }
                    }
                    catch (Exception ex)
                    {
                        _rejectedItems.Add($"ExcludedGroups[{i}]: '{group}' - Validation error: {ex.Message}");
                    }
                }
            }

            if (rawConfig.ExcludedUsers != null)
            {
                for (int i = 0; i < rawConfig.ExcludedUsers.Count; i++)
                {
                    var user = rawConfig.ExcludedUsers[i];
                    if (string.IsNullOrWhiteSpace(user))
                    {
                        _rejectedItems.Add($"ExcludedUsers[{i}]: Empty entry - not excluded");
                        continue;
                    }

                    try
                    {
                        var result = ValidateAndFixAccount(user, jsonContent);
                        if (result.IsValid)
                        {
                            validUsers.Add(result.FixedValue ?? user);
                            if (result.WasFixed)
                            {
                                fixedItems.Add($"ExcludedUsers[{i}]: '{user}' -> '{result.FixedValue}' (auto-fixed single backslash)");
                            }
                        }
                        else
                        {
                            _rejectedItems.Add($"ExcludedUsers[{i}]: '{user}' - {result.ErrorReason}");
                        }
                    }
                    catch (Exception ex)
                    {
                        _rejectedItems.Add($"ExcludedUsers[{i}]: '{user}' - Validation error: {ex.Message}");
                    }
                }
            }

            if (fixedItems.Count > 0)
            {
                Logger.LogInfo($"Auto-fixed {fixedItems.Count} exclusion(s) with single backslash issues:");
                foreach (var fix in fixedItems)
                {
                    Logger.LogInfo($"  {fix}");
                }
            }

            if (_rejectedItems.Count > 0)
            {
                Logger.LogWarning($"Rejected {_rejectedItems.Count} invalid exclusion(s):");
                foreach (var reject in _rejectedItems)
                {
                    Logger.LogWarning($"  {reject}");
                }
            }

            Logger.LogInfo($"Loaded {validGroups.Count} excluded group(s) and {validUsers.Count} excluded user(s)");
            if (validGroups.Count > 0)
            {
                Logger.LogInfo($"  Groups: {string.Join(", ", validGroups)}");
            }
            if (validUsers.Count > 0)
            {
                Logger.LogInfo($"  Users: {string.Join(", ", validUsers)}");
            }

            return new StelarkConfig
            {
                ExcludedGroups = validGroups,
                ExcludedUsers = validUsers,
                TechnicalConstants = rawConfig.TechnicalConstants ?? new TechnicalConstantsConfig()
            };
        }

        private static string FixSingleBackslashInJson(string jsonContent)
        {
            var lines = jsonContent.Split('\n');
            var fixedLines = new List<string>();
            bool wasFixed = false;

            foreach (var line in lines)
            {
                var fixedLine = System.Text.RegularExpressions.Regex.Replace(line, 
                    @"""([^""]*?)([^\\])\\([^\\""/bfnrtu])([^""]*?)""",
                    match =>
                    {
                        var before = match.Groups[1].Value;
                        var charBefore = match.Groups[2].Value;
                        var charAfter = match.Groups[3].Value;
                        var after = match.Groups[4].Value;
                        
                        if (!charAfter.All(c => char.IsLetterOrDigit(c) || c == '.' || c == '-' || c == '_'))
                        {
                            return match.Value;
                        }
                        
                        wasFixed = true;
                        return $"\"{before}{charBefore}\\\\{charAfter}{after}\"";
                    });
                fixedLines.Add(fixedLine);
            }

            return wasFixed ? string.Join("\n", fixedLines) : jsonContent;
        }

        private static (bool IsValid, bool WasFixed, string? FixedValue, string? ErrorReason) ValidateAndFixAccount(string account, string jsonContent)
        {
            if (string.IsNullOrWhiteSpace(account))
                return (false, false, null, "Empty value - not excluded");

            var backslashCount = account.Count(c => c == '\\');

            if (account.StartsWith("\\") || account.EndsWith("\\"))
            {
                return (false, false, null, "Invalid format - starts or ends with backslash");
            }

            var invalidChars = new char[] { '&', '^', '*', '<', '>', '|', ':', '"', '/', '?', '\t', '\n', '\r' };
            var foundInvalidChars = account.Where(c => invalidChars.Contains(c)).Distinct().ToList();
            if (foundInvalidChars.Any())
            {
                var charsList = string.Join(", ", foundInvalidChars.Select(c => $"'{c}'"));
                return (false, false, null, $"Invalid characters in account name: {charsList}");
            }

            if (backslashCount == 1)
            {
                return (true, false, account, null);
            }

            if (backslashCount > 1)
            {
                if (account.Contains("\\\\"))
                {
                    var doubleBackslashCount = (account.Length - account.Replace("\\\\", "").Length) / 2;
                    if (doubleBackslashCount > 1)
                    {
                        return (false, false, null, "Invalid format - multiple double backslashes (use exactly 2 backslashes: 'DOMAIN\\\\USERNAME')");
                    }
                    
                    var singleBackslashCount = backslashCount - (doubleBackslashCount * 2);
                    if (singleBackslashCount > 0)
                    {
                        return (false, false, null, "Invalid format - mixed backslash pattern (use exactly 2 backslashes: 'DOMAIN\\\\USERNAME')");
                    }
                }
                else
                {
                    return (false, false, null, $"Invalid format - multiple single backslashes ({backslashCount} found, use exactly 2 backslashes: 'DOMAIN\\\\USERNAME')");
                }
            }

            return (true, false, null, null);
        }

        private static string? ExtractProblematicValueFromJson(string jsonContent, JsonException ex)
        {
            try
            {
                if (string.IsNullOrEmpty(ex.Path))
                    return null;

                var pathMatch = System.Text.RegularExpressions.Regex.Match(ex.Path, @"(ExcludedUsers|ExcludedGroups)\[(\d+)\]");
                if (!pathMatch.Success)
                    return null;

                var arrayName = pathMatch.Groups[1].Value;
                var index = int.Parse(pathMatch.Groups[2].Value);

                var arrayPattern = arrayName == "ExcludedUsers"
                    ? @"""ExcludedUsers""\s*:\s*\[(.*?)\]"
                    : @"""ExcludedGroups""\s*:\s*\[(.*?)\]";

                var arrayMatch = System.Text.RegularExpressions.Regex.Match(
                    jsonContent,
                    arrayPattern,
                    System.Text.RegularExpressions.RegexOptions.Singleline | System.Text.RegularExpressions.RegexOptions.IgnoreCase
                );

                if (arrayMatch.Success)
                {
                    var arrayContent = arrayMatch.Groups[1].Value;
                    var items = System.Text.RegularExpressions.Regex.Matches(
                        arrayContent,
                        @"""((?:[^""\\]|\\.)*)"""
                    );

                    if (index < items.Count)
                    {
                        return items[index].Groups[1].Value;
                    }
                }
            }
            catch
            {
            }

            return null;
        }

        private static int ExtractIndexFromPath(string? path)
        {
            if (string.IsNullOrEmpty(path))
                return -1;

            var match = System.Text.RegularExpressions.Regex.Match(path, @"\[(\d+)\]");
            if (match.Success && int.TryParse(match.Groups[1].Value, out int index))
            {
                return index;
            }

            return -1;
        }

        public static void LogConfigDetails()
        {
            if (_config == null)
                return;

            Logger.LogInfo($"Configuration file: {(_configFileExists ? _configFilePath : "Not found (using defaults)")}");
            Logger.LogInfo($"Configuration validation: {(_configValidated ? "Valid" : "Invalid")}");

            if (!string.IsNullOrEmpty(_jsonError))
            {
                Logger.LogWarning(_jsonError);
                ConsoleHelper.WriteWarning(_jsonError);
            }

            var excludedGroupsCount = _config.ExcludedGroups?.Count ?? 0;
            var excludedUsersCount = _config.ExcludedUsers?.Count ?? 0;

            Logger.LogInfo($"Excluded groups: {excludedGroupsCount}");
            if (excludedGroupsCount > 0 && _config.ExcludedGroups != null)
            {
                Logger.LogInfo($"  Groups: {string.Join(", ", _config.ExcludedGroups)}");
            }

            Logger.LogInfo($"Excluded users: {excludedUsersCount}");
            if (excludedUsersCount > 0 && _config.ExcludedUsers != null)
            {
                Logger.LogInfo($"  Users: {string.Join(", ", _config.ExcludedUsers)}");
            }

            if (_rejectedItems.Count > 0)
            {
                Logger.LogWarning($"Rejected {_rejectedItems.Count} invalid exclusion(s) (not loaded):");
                foreach (var reject in _rejectedItems)
                {
                    Logger.LogWarning($"  {reject}");
                    ConsoleHelper.WriteWarning(reject);
                }
            }
        }

        public static void ShowConfigWarningIfNeeded()
        {
            if (_configWasMissing && !string.IsNullOrEmpty(_missingConfigPath))
            {
                ConsoleHelper.WriteWarning($"Configuration file not found at: {_missingConfigPath}");
                ConsoleHelper.WriteWarning("Using default configuration values. A default config file will be created.");
                _configWasMissing = false;
            }
        }

        public static void SaveConfig(StelarkConfig config, string? configPath = null)
        {
            if (string.IsNullOrEmpty(configPath))
            {
                configPath = Path.Combine(AppContext.BaseDirectory, "Stelark.config");
            }

            try
            {
                var options = new JsonSerializerOptions
                {
                    WriteIndented = true,
                    Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
                };
                var jsonContent = JsonSerializer.Serialize(config, options);
                jsonContent = AddConfigComments(jsonContent);
                File.WriteAllText(configPath, jsonContent);
                Logger.LogInfo($"Config file saved to {configPath}");
            }
            catch (Exception ex)
            {
                Logger.LogError($"Failed to save config file: {ex.Message}", ex);
            }
        }

        private static string AddConfigComments(string jsonContent)
        {
            if (string.IsNullOrEmpty(jsonContent))
                return jsonContent;

            var lines = jsonContent.Split('\n');
            var result = new List<string>();
            
            foreach (var line in lines)
            {
                var trimmedLine = line.Trim();
                
                if (trimmedLine.StartsWith("\"ExcludedGroups\""))
                {
                    result.Add("  // Format: DOMAIN\\\\GroupName or GroupName (use double backslash in JSON for domain format)");
                }
                else if (trimmedLine.StartsWith("\"ExcludedUsers\""))
                {
                    result.Add("  // Format: DOMAIN\\\\Username (use double backslash in JSON)");
                    result.Add("  // Example: \"DOMAIN\\\\Username\"");
                }
                
                result.Add(line);
            }
            
            return string.Join("\n", result);
        }

        private static int GetLineNumberFromJsonError(string jsonContent, JsonException ex)
        {
            try
            {
                if (ex.BytePositionInLine.HasValue)
                {
                    var lines = jsonContent.Substring(0, (int)ex.BytePositionInLine.Value).Split('\n');
                    return lines.Length;
                }
            }
            catch
            {
            }
            return 0;
        }

        private static StelarkConfig? TryExtractPartialConfig(string jsonContent, List<string> errors)
        {
            var config = CreateDefaultConfig();
            bool extractedAny = false;

            try
            {
                var groupsMatch = System.Text.RegularExpressions.Regex.Match(
                    jsonContent,
                    @"""ExcludedGroups""\s*:\s*\[(.*?)\]",
                    System.Text.RegularExpressions.RegexOptions.Singleline | System.Text.RegularExpressions.RegexOptions.IgnoreCase
                );

                if (groupsMatch.Success)
                {
                    var groupsContent = groupsMatch.Groups[1].Value;
                    var groups = ExtractStringArray(groupsContent, "ExcludedGroups", errors);
                    if (groups.Count > 0)
                    {
                        config.ExcludedGroups = groups;
                        extractedAny = true;
                        Logger.LogInfo($"Extracted {groups.Count} excluded groups from config (partial load)");
                    }
                }
                else
                {
                    errors.Add("Could not find 'ExcludedGroups' array in config file");
                }
            }
            catch (Exception ex)
            {
                errors.Add($"Failed to extract ExcludedGroups: {ex.Message}");
                Logger.LogError($"Failed to extract ExcludedGroups: {ex.Message}", ex);
            }

            try
            {
                var usersMatch = System.Text.RegularExpressions.Regex.Match(
                    jsonContent,
                    @"""ExcludedUsers""\s*:\s*\[(.*?)\]",
                    System.Text.RegularExpressions.RegexOptions.Singleline | System.Text.RegularExpressions.RegexOptions.IgnoreCase
                );

                if (usersMatch.Success)
                {
                    var usersContent = usersMatch.Groups[1].Value;
                    var users = ExtractStringArray(usersContent, "ExcludedUsers", errors);
                    if (users.Count > 0)
                    {
                        config.ExcludedUsers = users;
                        extractedAny = true;
                        Logger.LogInfo($"Extracted {users.Count} excluded users from config (partial load)");
                    }
                }
                else
                {
                    errors.Add("Could not find 'ExcludedUsers' array in config file");
                }
            }
            catch (Exception ex)
            {
                errors.Add($"Failed to extract ExcludedUsers: {ex.Message}");
                Logger.LogError($"Failed to extract ExcludedUsers: {ex.Message}", ex);
            }

            return extractedAny ? config : null;
        }

        private static List<string> ExtractStringArray(string arrayContent, string arrayName, List<string> errors)
        {
            var items = new List<string>();
            var lines = arrayContent.Split('\n');
            int index = 0;

            foreach (var line in lines)
            {
                var trimmed = line.Trim();
                if (string.IsNullOrEmpty(trimmed) || trimmed == "," || trimmed.StartsWith("//"))
                    continue;

                var matches = System.Text.RegularExpressions.Regex.Matches(
                    trimmed,
                    @"""((?:[^""\\]|\\.)*)"""
                );

                foreach (System.Text.RegularExpressions.Match match in matches)
                {
                    if (match.Groups.Count > 1)
                    {
                        var value = match.Groups[1].Value;
                        value = value.Replace("\\\"", "\"").Replace("\\\\", "\\").Replace("\\n", "\n").Replace("\\r", "\r").Replace("\\t", "\t");
                        
                        if (!string.IsNullOrWhiteSpace(value))
                        {
                            items.Add(value);
                        }
                    }
                }

                if (!string.IsNullOrWhiteSpace(trimmed) && 
                    !trimmed.StartsWith("//") && 
                    !trimmed.StartsWith("/*") && 
                    matches.Count == 0 &&
                    !trimmed.Contains("\""))
                {
                    errors.Add($"{arrayName}[{index}]: Could not parse value from line: '{trimmed.Trim()}'");
                }
                index++;
            }

            return items;
        }

        private static StelarkConfig CreateDefaultConfig()
        {
            return new StelarkConfig
            {
                ExcludedGroups = new List<string>
                {
                    "Domain Admins", "Enterprise Admins", "Administrators", "Schema Admins",
                    "Account Operators", "Server Operators", "Backup Operators", "Print Operators",
                    "Cert Publishers", "Group Policy Creator Owners", "Builtin\\\\Administrators",
                    "DNS Admins", "Exchange Admins", "Organization Management", "Security Admins",
                    "Security Operators", "System Managed", "Domain Controllers", "Enterprise Domain Controllers", "RAS and IAS Servers",
                    "Certificate Managers", "CA Administrators",
                    "S-1-5-32-544", "S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-550", "S-1-5-32-551",
                    "S-1-5-32-522", "S-1-5-18", "S-1-5-32-555", "S-1-5-32-520"
                },
                ExcludedUsers = new List<string>(),
                TechnicalConstants = new TechnicalConstantsConfig
                {
                    AuthEKUs = new List<string>
                    {
                        "1.3.6.1.5.5.7.3.2",
                        "1.3.6.1.4.1.311.20.2.2",
                        "1.3.6.1.5.2.3.4"
                    },
                    ESC2EKUs = new List<string>
                    {
                        "2.5.29.37.0"
                    },
                    ESC3EKUs = new List<string>
                    {
                        "1.3.6.1.4.1.311.20.2.1",
                        "Certificate Request Agent"
                    },
                    EnrollGuid = "0e10c968-78fb-11d2-90d4-00c04f79dc55",
                    AutoenrollGuid = "a05b8cc2-17bc-4802-a710-e7c15ab866a2",
                    EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000
                }
            };
        }
    }
}



