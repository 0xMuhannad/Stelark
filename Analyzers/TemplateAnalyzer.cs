using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using Stelark.Core;
using Stelark.Models;
using Stelark.Helpers;
using Stelark.Services;
using AccountType = Stelark.Helpers.AccountType;
using SecurityIdentifier = System.Security.Principal.SecurityIdentifier;

namespace Stelark.Analyzers
{
    public class TemplateAnalyzer
    {
        private readonly GlobalState _state;

        public TemplateAnalyzer(GlobalState state)
        {
            _state = state;
        }

        public void FindESC1VulnerableTemplates()
        {
            if (!_state.IsLocalCAServer)    
            {
                Logger.LogInfo("ESC1 template analysis skipped - No local CA server access");
                _state.ESC1VulnTemplates.Clear();
                return;
            }

            if (_state.CachedTemplates?.IsValid == true && _state.CachedTemplates.ESC1Templates.Any())
            {
                Logger.LogInfo("Using cached ESC1 vulnerable templates");
                _state.ESC1VulnTemplates = _state.CachedTemplates.ESC1Templates;
                return;
            }

            ConsoleHelper.WriteInfo("Enumerating vulnerable certificate templates to ESC1...");
            Logger.LogInfo("Enumerating vulnerable certificate templates to ESC1...");
            
            _state.ESC1VulnTemplates = FindVulnerableTemplatesGeneric(
                authEKUs: Constants.AuthEKUs,
                allowNoEku: false,
                allowAnyPurpose: false,
                mode: "EKU"
            );
            
            if (_state.CachedTemplates == null)
                _state.CachedTemplates = new TemplateCache();
            _state.CachedTemplates.ESC1Templates = _state.ESC1VulnTemplates;
            _state.CachedTemplates.CacheTime = DateTime.Now;
        }

        public void FindESC2VulnerableTemplates()
        {
            if (!_state.IsLocalCAServer)
            {
                _state.ESC2VulnTemplates.Clear();
                return;
            }

            if (_state.CachedTemplates?.IsValid == true && _state.CachedTemplates.ESC2Templates.Any())
            {
                Logger.LogInfo("Using cached ESC2 vulnerable templates");
                _state.ESC2VulnTemplates = _state.CachedTemplates.ESC2Templates;
                return;
            }

            ConsoleHelper.WriteInfo("Enumerating vulnerable certificate templates to ESC2...");
            Logger.LogInfo("Enumerating vulnerable certificate templates to ESC2...");
            
            _state.ESC2VulnTemplates = FindVulnerableTemplatesGeneric(
                authEKUs: Constants.ESC2EKUs,
                allowNoEku: true,
                allowAnyPurpose: true,
                mode: "EKU"
            );
            
            if (_state.CachedTemplates == null)
                _state.CachedTemplates = new TemplateCache();
            _state.CachedTemplates.ESC2Templates = _state.ESC2VulnTemplates;
            _state.CachedTemplates.CacheTime = DateTime.Now;
        }

        public void FindESC3VulnerableTemplates()
        {
            if (!_state.IsLocalCAServer)
            {
                _state.ESC3VulnTemplates.Clear();
                return;
            }

            if (_state.CachedTemplates?.IsValid == true && _state.CachedTemplates.ESC3Templates.Any())
            {
                Logger.LogInfo("Using cached ESC3 vulnerable templates");
                _state.ESC3VulnTemplates = _state.CachedTemplates.ESC3Templates;
                return;
            }

            ConsoleHelper.WriteInfo("Enumerating vulnerable certificate templates to ESC3...");
            Logger.LogInfo("Enumerating vulnerable certificate templates to ESC3...");
            
            _state.ESC3VulnTemplates = FindVulnerableTemplatesGeneric(
                authEKUs: Constants.ESC3EKUs,
                allowNoEku: false,
                allowAnyPurpose: false,
                mode: "EKU"
            );
            
            if (_state.CachedTemplates == null)
                _state.CachedTemplates = new TemplateCache();
            _state.CachedTemplates.ESC3Templates = _state.ESC3VulnTemplates;
            _state.CachedTemplates.CacheTime = DateTime.Now;
        }

        public void FindESC4VulnerableTemplates()
        {
            if (!_state.IsLocalCAServer)
            {
                _state.ESC4VulnTemplates.Clear();
                return;
            }

            if (_state.CachedTemplates?.IsValid == true && _state.CachedTemplates.ESC4Templates.Any())
            {
                Logger.LogInfo("Using cached ESC4 vulnerable templates");
                _state.ESC4VulnTemplates = _state.CachedTemplates.ESC4Templates;
                return;
            }

            ConsoleHelper.WriteInfo("Enumerating vulnerable certificate templates to ESC4...");
            Logger.LogInfo("Enumerating vulnerable certificate templates to ESC4...");
            
            var privilegedSids = BuildPrivilegedSidsLookup();
            
            _state.ESC4VulnTemplates = FindVulnerableTemplatesGeneric(
                privilegedSids: privilegedSids,
                mode: "DACL"
            );
            
            if (_state.CachedTemplates == null)
                _state.CachedTemplates = new TemplateCache();
            _state.CachedTemplates.ESC4Templates = _state.ESC4VulnTemplates;
            _state.CachedTemplates.CacheTime = DateTime.Now;
        }

        private List<VulnerableTemplate> FindVulnerableTemplatesGeneric(
            string[]? authEKUs = null,
            bool allowNoEku = false,
            bool allowAnyPurpose = false,
            HashSet<string>? privilegedSids = null,
            string mode = "EKU")
        {
            try
            {
                Logger.LogInfo($"Starting template enumeration for {mode} mode");
                var timer = System.Diagnostics.Stopwatch.StartNew();
                
                var enrollRightGuids = new[] { Constants.EnrollGuid, Constants.AutoenrollGuid };
                
                Logger.LogInfo("Getting published certificate templates...");
                var publishedTimer = System.Diagnostics.Stopwatch.StartNew();
                var publishedTemplates = GetPublishedCertificateTemplates();
                publishedTimer.Stop();
                
                Logger.LogInfo("Getting all certificate templates from AD...");
                var allTemplatesTimer = System.Diagnostics.Stopwatch.StartNew();
                var results = GetAllCertificateTemplates();
                allTemplatesTimer.Stop();
                Logger.LogInfo($"All templates retrieved in {allTemplatesTimer.ElapsedMilliseconds}ms, found {results?.Count ?? 0} templates");
                var vulnTemplates = new List<VulnerableTemplate>();

                                if (results == null)
                {
                    return vulnTemplates;
                }
                

                
                var templateLookup = BuildTemplateLookup(results);
                var templateCount = 1;

                foreach (SearchResult result in results)
                {
                    if (mode == "EKU")
                    {
                        var template = ProcessEKUTemplate(result, authEKUs!, allowNoEku, allowAnyPurpose, 
                            enrollRightGuids, publishedTemplates, templateLookup, templateCount);
                        
                        if (template != null)
                        {
                            vulnTemplates.Add(template);
                            templateCount++;
                        }
                    }
                    else if (mode == "DACL")
                    {
                        var template = ProcessDACLTemplate(result, privilegedSids!, templateCount, publishedTemplates);
                        
                        if (template != null)
                        {
                            vulnTemplates.Add(template);
                            templateCount++;
                        }
                    }
                }

                Logger.LogQuery("Template Analysis", "Active Directory", vulnTemplates.Count);
                Logger.LogStatistic("Vulnerable Templates", vulnTemplates.Count, "templates matching vulnerability criteria");
                Logger.LogStatistic("Templates Analyzed", templateCount, "total templates examined in AD");
                
                foreach (var template in vulnTemplates)
                {
                    Logger.LogVulnerability("Template Analysis", template.DisplayName, 
                        $"Enabled: {template.IsEnabled}, Enrollment Groups: {string.Join(", ", template.EnrollmentGroups)}");
                }
                
                return vulnTemplates;
            }
            catch (Exception ex)
            {
                Logger.LogError($"An error occurred while enumerating vulnerable certificate templates in {mode} mode", ex);
                ConsoleHelper.WriteError($"An error occurred while enumerating vulnerable certificate templates: {ex.Message}");
                return new List<VulnerableTemplate>();
            }
        }

        private VulnerableTemplate? ProcessEKUTemplate(
            SearchResult result,
            string[] authEKUs,
            bool allowNoEku,
            bool allowAnyPurpose,
            Guid[] enrollRightGuids,
            Dictionary<string, bool> publishedTemplates,
            Dictionary<string, TemplateInfo> templateLookup,
            int templateCount)
        {
            var displayName = result.Properties["displayName"]?[0]?.ToString()!;
            var cn = result.Properties["cn"]?[0]?.ToString()!;
            
            string? oid = null;
            if (templateLookup.ContainsKey(displayName))
                oid = templateLookup[displayName].OID;
            else if (templateLookup.ContainsKey(cn))
                oid = templateLookup[cn].OID;

            var enrollmentFlag = GetPropertyValue<int>(result, "msPKI-Enrollment-Flag");
            var nameFlag = GetPropertyValue<int>(result, "msPKI-Certificate-Name-Flag");
            var raSignature = GetPropertyValue<int>(result, "msPKI-RA-Signature");

            var ekuList = new List<string>();
            if (result.Properties["pKIExtendedKeyUsage"].Count > 0)
                ekuList.AddRange(result.Properties["pKIExtendedKeyUsage"].Cast<string>());
            if (result.Properties["msPKI-Certificate-Application-Policy"].Count > 0)
                ekuList.AddRange(result.Properties["msPKI-Certificate-Application-Policy"].Cast<string>());

            var suppliesSubject = (nameFlag & 0x1) == 0x1;
            var noManagerApproval = (enrollmentFlag & 0x2) == 0;
            var noRASignature = raSignature == 0;

            var hasAuthEKU = false;
            var hasCertRequestAgentEKU = false;
            var hasAnyPurposeEKU = false;
            var hasNoEKU = false;
            
            if (allowNoEku && ekuList.Count == 0)
            {
                hasNoEKU = true;
                if (authEKUs.SequenceEqual(Constants.ESC2EKUs))
                {
                    hasAuthEKU = false;
                }
                else
                {
                    hasAuthEKU = true;
                }
            }
            else if (allowAnyPurpose && ekuList.Contains("2.5.29.37.0"))
            {
                hasAnyPurposeEKU = true;
                if (authEKUs.SequenceEqual(Constants.ESC2EKUs))
                {
    
                    hasAuthEKU = false;
                }
                else
                {
                    hasAuthEKU = true;
                }
            }
            else
            {
                if (authEKUs.SequenceEqual(Constants.ESC3EKUs))
                {
                    hasCertRequestAgentEKU = ekuList.Any(eku => authEKUs.Contains(eku));
                    hasAuthEKU = false;
                }
                else
                {
                    hasAuthEKU = ekuList.Any(eku => authEKUs.Contains(eku));
                }
            }
            
            var enrollInfo = GetTemplateEnrollmentInfo(result, enrollRightGuids);
            var hasEnroll = enrollInfo.HasEnroll;
                var enrollGroups = enrollInfo.EnrollmentGroups;

            string currentESCType = "";
            if (authEKUs.SequenceEqual(Constants.ESC3EKUs)) currentESCType = "ESC3";
            else if (authEKUs.SequenceEqual(Constants.ESC2EKUs)) currentESCType = "ESC2";
            else currentESCType = "ESC1";

            bool willBeVulnerable = false;
            if (authEKUs.SequenceEqual(Constants.ESC3EKUs))
            {
                willBeVulnerable = noManagerApproval && noRASignature && hasCertRequestAgentEKU && hasEnroll;
            }
            else if (authEKUs.SequenceEqual(Constants.ESC2EKUs))
            {
                willBeVulnerable = noManagerApproval && noRASignature && (hasAnyPurposeEKU || hasNoEKU) && hasEnroll;
            }
            else
            {
                willBeVulnerable = suppliesSubject && noManagerApproval && noRASignature && hasAuthEKU && hasEnroll;
            }

            if (willBeVulnerable)
            {
                Logger.LogTemplateAnalysis(displayName, "SuppliesSubject", suppliesSubject.ToString(), suppliesSubject ? "Allows requesters to specify subject" : "Subject supplied by template", currentESCType);
                Logger.LogTemplateAnalysis(displayName, "ManagerApproval", (!noManagerApproval).ToString(), noManagerApproval ? "No approval required" : "Manager approval required", currentESCType);
                Logger.LogTemplateAnalysis(displayName, "RASignature", (!noRASignature).ToString(), noRASignature ? "No RA signature required" : "RA signature required", currentESCType);
                if (hasEnroll)
                {
                    Logger.LogTemplateAnalysis(displayName, "HasEnroll", hasEnroll.ToString(), $"Has enrollment permissions - {enrollGroups.Count} non-privileged group(s)", currentESCType);
                    for (int i = 0; i < enrollGroups.Count; i++)
                    {
                        Logger.LogTemplateAnalysis(displayName, $"EnrollGroup{i + 1}", enrollGroups[i], $"Non-privileged group with enrollment access", currentESCType);
                    }
                }
                else
                {
                    Logger.LogTemplateAnalysis(displayName, "HasEnroll", hasEnroll.ToString(), "No enrollment permissions for non-privileged groups", currentESCType);
                }
                Logger.LogTemplateAnalysis(displayName, "EKUs", string.Join(", ", ekuList), $"Extended Key Usages defined", currentESCType);

                if (enrollInfo.ExcludedAccounts.Count > 0)
                {
                    Logger.LogInfo($"Template '{displayName}': Excluded accounts: {string.Join(", ", enrollInfo.ExcludedAccounts.Distinct())}");
                }
            }

            bool isVulnerable = false;
            string escType = "";
            string vulnerabilityDecision = "";
            
            if (authEKUs.SequenceEqual(Constants.ESC3EKUs))
            {
                escType = "ESC3";
                Logger.LogTemplateAnalysis(displayName, "HasCertRequestAgentEKU", hasCertRequestAgentEKU.ToString(), hasCertRequestAgentEKU ? "Certificate Request Agent EKU present" : "No Certificate Request Agent EKU", currentESCType);
                
                isVulnerable = noManagerApproval && noRASignature && hasCertRequestAgentEKU && hasEnroll;
                vulnerabilityDecision = $"ManagerApproval:{!noManagerApproval}, RASignature:{!noRASignature}, CertRequestAgent:{hasCertRequestAgentEKU}, HasEnroll:{hasEnroll}";
            }
            else if (authEKUs.SequenceEqual(Constants.ESC2EKUs))
            {
                escType = "ESC2";
                Logger.LogTemplateAnalysis(displayName, "HasAnyPurposeEKU", hasAnyPurposeEKU.ToString(), hasAnyPurposeEKU ? "Any Purpose EKU present" : "No Any Purpose EKU", currentESCType);
                Logger.LogTemplateAnalysis(displayName, "HasNoEKU", hasNoEKU.ToString(), hasNoEKU ? "No EKUs defined" : "EKUs are defined", currentESCType);
                
                isVulnerable = noManagerApproval && noRASignature && (hasAnyPurposeEKU || hasNoEKU) && hasEnroll;
                vulnerabilityDecision = $"ManagerApproval:{!noManagerApproval}, RASignature:{!noRASignature}, AnyPurpose/NoEKU:{hasAnyPurposeEKU || hasNoEKU}, HasEnroll:{hasEnroll}";
            }
            else
            {
                escType = "ESC1";
                Logger.LogTemplateAnalysis(displayName, "HasAuthEKU", hasAuthEKU.ToString(), hasAuthEKU ? "Authentication EKU present" : "No Authentication EKU", currentESCType);
                
                isVulnerable = suppliesSubject && noManagerApproval && noRASignature && hasAuthEKU && hasEnroll;
                vulnerabilityDecision = $"SuppliesSubject:{suppliesSubject}, ManagerApproval:{!noManagerApproval}, RASignature:{!noRASignature}, AuthEKU:{hasAuthEKU}, HasEnroll:{hasEnroll}";
            }
            
            Core.PerformanceMetrics.IncrementTemplateAnalyzed(isVulnerable);
            
            Logger.LogTemplateDecision(displayName, escType, isVulnerable, vulnerabilityDecision);
            
            if (isVulnerable)
            {
                var isEnabled = publishedTemplates.ContainsKey(displayName) || publishedTemplates.ContainsKey(cn);
                Logger.LogTemplateAnalysis(displayName, "IsEnabled", isEnabled.ToString(), isEnabled ? "Template is published to CA" : "Template is not published", currentESCType);
                
    
                string vulnerabilityReason = "";
                if (authEKUs.SequenceEqual(Constants.ESC2EKUs))
                {
                    if (ekuList.Count == 0)
                        vulnerabilityReason = "No EKU";
                    else if (ekuList.Contains("2.5.29.37.0"))
                        vulnerabilityReason = "Any Purpose";
                    else
                        vulnerabilityReason = "Other EKU";
                }
                else if (authEKUs.SequenceEqual(Constants.AuthEKUs))
                {
                    vulnerabilityReason = "Client Authentication";
                }
                else if (authEKUs.SequenceEqual(Constants.ESC3EKUs))
                {
                    vulnerabilityReason = "Certificate Request Agent";
                }
                
                return new VulnerableTemplate
                {
                    TemplateCount = templateCount,
                    DisplayName = displayName,
                    CN = cn,
                    OID = oid,
                    IsEnabled = isEnabled,
                    SuppliesSubject = suppliesSubject,
                    NoManagerApproval = noManagerApproval,
                    NoRASignature = noRASignature,
                    HasAuthEKU = hasAuthEKU,
                    HasCertRequestAgentEKU = hasCertRequestAgentEKU,
                    HasAnyPurposeEKU = hasAnyPurposeEKU,
                    HasNoEKU = hasNoEKU,
                    HasEnroll = hasEnroll,
                    EnrollmentGroups = enrollGroups,
                    EKUs = ekuList,
                    VulnerabilityReason = vulnerabilityReason
                };
            }



            return null;
        }

        private VulnerableTemplate? ProcessDACLTemplate(
            SearchResult result,
            HashSet<string> privilegedSids,
            int templateCount,
            Dictionary<string, bool>? publishedTemplates = null)
        {
            var vulnerableACEs = new List<RiskyGroup>();
            var displayName = result.Properties["displayName"][0].ToString()!;
            
            if (result.Properties["nTSecurityDescriptor"].Count > 0)
            {
                var sdBytes = (byte[])result.Properties["nTSecurityDescriptor"][0];
                var rawSD = new RawSecurityDescriptor(sdBytes, 0);
                var dacl = rawSD.DiscretionaryAcl;

                if (dacl != null)
                {
                    foreach (var ace in dacl)
                    {
                        if (ace is CommonAce commonAce && commonAce.AceType == AceType.AccessAllowed)
                        {
                            var principalSid = commonAce.SecurityIdentifier.Value;
                            
                            var foundDangerousRights = new List<string>();
                                if ((commonAce.AccessMask & (int)ActiveDirectoryRights.GenericAll) == (int)ActiveDirectoryRights.GenericAll)
                                    foundDangerousRights.Add("FullControl");
                                if ((commonAce.AccessMask & (int)ActiveDirectoryRights.WriteDacl) == (int)ActiveDirectoryRights.WriteDacl)
                                    foundDangerousRights.Add("WriteDacl");
                                if ((commonAce.AccessMask & (int)ActiveDirectoryRights.WriteOwner) == (int)ActiveDirectoryRights.WriteOwner)
                                    foundDangerousRights.Add("WriteOwner");

                                if (foundDangerousRights.Count > 0)
                                {
                                    try
                                    {
                                        var ntAccount = commonAce.SecurityIdentifier.Translate(typeof(NTAccount)).Value;
                                    var accountName = ntAccount.Split('\\').LastOrDefault() ?? ntAccount;
                                    
                                    Logger.LogTemplateAnalysis(displayName, "CheckingACE", ntAccount, $"Checking permissions: {string.Join(", ", foundDangerousRights)}", "ESC4");
                                    
                                    if (ShouldExcludeAccount(accountName, ntAccount))
                                    {
                                        Logger.LogTemplateAnalysis(displayName, "ExcludedACE", "SKIPPED", $"Account '{ntAccount}' excluded from vulnerability reporting (machine account or CA server)", "ESC4");
                                        continue;
                                    }
                                    
                                    var isPrivilegedBySid = privilegedSids.Contains(principalSid);
                                    Logger.LogTemplateAnalysis(displayName, "PrivilegedBySID", isPrivilegedBySid.ToString(), $"SID {principalSid} in privileged list: {isPrivilegedBySid}", "ESC4");
                                    
                                    var isPrivilegedByName = IsPrivilegedGroupForTemplate(accountName);
                                    Logger.LogTemplateAnalysis(displayName, "PrivilegedByName", isPrivilegedByName.ToString(), $"Account '{accountName}' is privileged by name: {isPrivilegedByName}", "ESC4");
                                    
                                    var isPrivilegedByGroupMembership = false;
                                    if (!isPrivilegedBySid && !isPrivilegedByName)
                                    {
                                        try
                                        {
                                            AccountType accountType = AdHelper.GetAccountType(accountName);
                                            
                                            if (accountType == AccountType.User)
                                            {
                                                var userGroups = GetUserGroupMemberships(accountName);
                                                foreach (var group in userGroups)
                                                {
                                                    if (IsPrivilegedGroupForTemplate(group))
                                                    {
                                                        isPrivilegedByGroupMembership = true;
                                                        Logger.LogTemplateAnalysis(displayName, "PrivilegedByGroup", "TRUE", $"User '{accountName}' belongs to privileged group: {group}", "ESC4");
                                                        break;
                                                    }
                                                }
                                                if (!isPrivilegedByGroupMembership && userGroups.Count > 0)
                                                {
                                                    Logger.LogTemplateAnalysis(displayName, "UserGroups", string.Join(", ", userGroups), $"User '{accountName}' group memberships checked - none privileged", "ESC4");
                                                }
                                            }
                                            else if (accountType == AccountType.Group)
                                            {
                                            }
                                        }
                                        catch (Exception ex)
                                        {
                                            Logger.LogError($"Failed to get group memberships for account '{accountName}'", ex);
                                        }
                                    }
                                    
                                    if (!isPrivilegedBySid && !isPrivilegedByName && !isPrivilegedByGroupMembership)
                                    {
                                        Logger.LogTemplateAnalysis(displayName, "VulnerableACE", "TRUE", $"Non-privileged account '{ntAccount}' has dangerous permissions: {string.Join(", ", foundDangerousRights)}", "ESC4");
                                        vulnerableACEs.Add(new RiskyGroup
                                        {
                                            Group = ntAccount,
                                            Rights = string.Join(", ", foundDangerousRights)
                                        });
                                    }
                                    else
                                    {
                                        var privilegeReason = isPrivilegedBySid ? "SID" : isPrivilegedByName ? "Name" : "Group Membership";
                                        Logger.LogTemplateAnalysis(displayName, "PrivilegedACE", "SKIPPED", $"Privileged account '{ntAccount}' (by {privilegeReason}) has expected permissions: {string.Join(", ", foundDangerousRights)}", "ESC4");
                                    }
                                    }
                                    catch (Exception ex)
                                    {
                                        Logger.LogError("Failed to translate SID to friendly name", ex);
                                    Logger.LogTemplateAnalysis(displayName, "UnknownSID", principalSid, $"Could not translate SID, checking against privileged SIDs only", "ESC4");
                                    
                                    if (!privilegedSids.Contains(principalSid))
                                    {
                                        Logger.LogTemplateAnalysis(displayName, "VulnerableACE", "TRUE", $"Non-privileged untranslatable SID '{principalSid}' has dangerous permissions: {string.Join(", ", foundDangerousRights)}", "ESC4");
                                        vulnerableACEs.Add(new RiskyGroup
                                        {
                                            Group = principalSid,
                                            Rights = string.Join(", ", foundDangerousRights)
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if (vulnerableACEs.Count > 0)
            {
                var oid = GetPropertyValue<string>(result, "msPKI-Cert-Template-OID");
                var cn = result.Properties["cn"][0].ToString()!;
                
                Logger.LogTemplateAnalysis(displayName, "DangerousACEs", vulnerableACEs.Count.ToString(), $"{vulnerableACEs.Count} dangerous ACE(s) found", "ESC4");
    
                var isEnabled = false;
                if (publishedTemplates != null)
                {
                    isEnabled = publishedTemplates.ContainsKey(displayName) || publishedTemplates.ContainsKey(cn);
                }
                
                return new VulnerableTemplate
                {
                    TemplateCount = templateCount,
                    DisplayName = displayName,
                    CN = cn,
                    OID = oid,
                    IsEnabled = isEnabled,
                    RiskyGroups = vulnerableACEs,
                    VulnerabilityReason = "Access Control"
                };
            }

            return null;
        }

        private HashSet<string> BuildPrivilegedSidsLookup()
        {
            var privilegedSids = new HashSet<string>();
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            Logger.LogInfo("Building privileged SIDs lookup...");
            
            try
            {

                DirectoryEntry? rootDSE = null;
                string? domainNC = null;

                Logger.LogInfo("Trying privileged SIDs LDAP connection method 1: Machine's domain (fast path)");
                try
                {
                    var machineName = Environment.MachineName;
                    var fqdn = System.Net.Dns.GetHostEntry(machineName).HostName;
                    
                    if (fqdn.Contains("."))
                    {
                        var domain = fqdn.Substring(fqdn.IndexOf(".") + 1);
                        rootDSE = new DirectoryEntry($"LDAP://{domain}/RootDSE", null, null, AuthenticationTypes.Secure);
                        domainNC = rootDSE.Properties["defaultNamingContext"]?[0]?.ToString();
                        Logger.LogInfo("Privileged SIDs LDAP connection method 1: SUCCESS");
                    }
                }
                catch (Exception ex)
                {
                    Logger.LogError("Privileged SIDs LDAP connection method 1 failed", ex);
                    Logger.LogInfo("Privileged SIDs LDAP connection method 1: FAILED - Trying method 2: DNS domain lookup");

                    try
                    {
                        var domainName = System.Net.Dns.GetHostEntry(Environment.MachineName).HostName;
                        if (domainName.Contains("."))
                        {
                            domainName = domainName.Substring(domainName.IndexOf(".") + 1);
                            rootDSE = new DirectoryEntry($"LDAP://{domainName}/RootDSE");
                            domainNC = rootDSE.Properties["defaultNamingContext"]?[0]?.ToString();
                            Logger.LogInfo("Privileged SIDs LDAP connection method 2: SUCCESS");
                        }
                    }
                    catch (Exception ex2)
                    {
                        Logger.LogError("Privileged SIDs LDAP connection method 2 failed", ex2);
                        Logger.LogInfo("Privileged SIDs LDAP connection method 2: FAILED - Trying method 3: localhost");
    
                        try
                        {
                            rootDSE = new DirectoryEntry("LDAP://localhost/RootDSE");
                            domainNC = rootDSE.Properties["defaultNamingContext"]?[0]?.ToString();
                            Logger.LogInfo("Privileged SIDs LDAP connection method 3: SUCCESS");
                        }
                        catch (Exception ex3)
                        {
                            Logger.LogError("Privileged SIDs LDAP connection method 3 failed", ex3);
                            Logger.LogInfo("Privileged SIDs LDAP connection method 3: FAILED - Trying method 4: RootDSE");
        
                            try
                            {
                                rootDSE = new DirectoryEntry("LDAP://RootDSE");
                                domainNC = rootDSE.Properties["defaultNamingContext"]?[0]?.ToString();
                                Logger.LogInfo("Privileged SIDs LDAP connection method 4: SUCCESS");
                            }
                            catch (Exception ex4)
                            {
                                Logger.LogError("All LDAP connection methods failed for privileged SIDs lookup", ex4);
                                ConsoleHelper.WriteError("Could not connect to any domain controller.");
                                return privilegedSids;
                            }
                        }
                    }
                }
                
                if (string.IsNullOrEmpty(domainNC))
                {
                    ConsoleHelper.WriteError("Could not determine default naming context.");
                    return privilegedSids;
                }


                DirectoryEntry domainEntry;
                if (rootDSE?.Path?.Contains("localhost") == true)
                {
                    domainEntry = new DirectoryEntry($"LDAP://localhost/{domainNC}");
                }
                else if (rootDSE?.Path?.Contains("LDAP://") == true && !rootDSE.Path.Contains("localhost"))
                {
                    var domainPart = rootDSE.Path.Replace("/RootDSE", "");
                    domainEntry = new DirectoryEntry($"{domainPart}/{domainNC}");
                }
                else
                {
                    domainEntry = new DirectoryEntry($"LDAP://{domainNC}");
                }

                using var searcher = new DirectorySearcher(domainEntry)
                {
                    PageSize = 1000
                };

                foreach (var groupName in Constants.ExcludedGroups)
                {
                    try
                    {
                        var groupStopwatch = System.Diagnostics.Stopwatch.StartNew();
                        searcher.Filter = $"(&(objectClass=group)(sAMAccountName={groupName}))";
                        searcher.PropertiesToLoad.Clear();
                        searcher.PropertiesToLoad.Add("objectSid");
                        searcher.PropertiesToLoad.Add("member");
                        
                        var groupResult = searcher.FindOne();
                        if (groupResult?.Properties["objectSid"].Count > 0)
                        {
                            var groupSid = new SecurityIdentifier((byte[])groupResult.Properties["objectSid"][0], 0).Value;
                            privilegedSids.Add(groupSid);

                            var memberCount = groupResult.Properties["member"].Count;
                            Logger.LogInfo($"Found privileged group '{groupName}' with {memberCount} members - using group SID only for performance");
                            
                        }
                        groupStopwatch.Stop();
                        Logger.LogInfo($"Group '{groupName}' processed in {groupStopwatch.ElapsedMilliseconds}ms");
                    }
                    catch (Exception ex)
                    {
                        Logger.LogError($"Failed to process privileged group '{groupName}'", ex);
                    }
                }

                Logger.LogInfo("Searching for additional privileged groups from config...");
                foreach (var excludedGroup in Constants.ExcludedGroups)
                {
                    if (string.IsNullOrEmpty(excludedGroup))
                        continue;
                    
                    var keyword = excludedGroup.ToLower().Trim();
                    try
                    {
                        searcher.Filter = $"(&(objectClass=group)(sAMAccountName=*{keyword}*))";
                        searcher.PropertiesToLoad.Clear();
                        searcher.PropertiesToLoad.Add("objectSid");
                        searcher.PropertiesToLoad.Add("sAMAccountName");
                        
                        var results = searcher.FindAll();
                        foreach (SearchResult result in results)
                        {
                            var groupName = result.Properties["sAMAccountName"][0]?.ToString();
                            if (!string.IsNullOrEmpty(groupName) && IsPrivilegedGroupForTemplate(groupName) && result.Properties["objectSid"].Count > 0)
                            {
                                var groupSid = new SecurityIdentifier((byte[])result.Properties["objectSid"][0], 0).Value;
                                if (!privilegedSids.Contains(groupSid))
                                {
                                    privilegedSids.Add(groupSid);
                                    Logger.LogInfo($"Found config-based privileged group '{groupName}' - added to privileged SIDs");
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.LogError($"Failed to search for groups with keyword '{keyword}'", ex);
                    }
                }


                foreach (var sid in Constants.ExcludedGroups)
                {
                    privilegedSids.Add(sid);
                }
            }
            catch (Exception ex)
            {
                Logger.LogError("Failed to build privileged SIDs lookup", ex);
                ConsoleHelper.WriteError($"Failed to build privileged SIDs lookup: {ex.Message}");
            }

            
            var ntStopwatch = System.Diagnostics.Stopwatch.StartNew();
            Logger.LogInfo($"Processing {Constants.ExcludedGroups.Length} other privileged groups via NTAccount translation");
            foreach (var groupName in Constants.ExcludedGroups)
            {
                try
                {
                    var ntAccount = new NTAccount(groupName);
                    var sid = (SecurityIdentifier)ntAccount.Translate(typeof(SecurityIdentifier));
                    privilegedSids.Add(sid.Value);
                }
                catch (IdentityNotMappedException)
                {

                }
                catch (Exception ex)
                {
                    Logger.LogError($"Could not resolve SID for privileged group '{groupName}'", ex);
                    ConsoleHelper.WriteWarning($"Could not resolve SID for privileged group '{groupName}': {ex.Message}");
                }
            }
            ntStopwatch.Stop();
            Logger.LogInfo($"NTAccount translations completed in {ntStopwatch.ElapsedMilliseconds}ms");

            stopwatch.Stop();
            Logger.LogInfo($"Privileged SIDs lookup completed in {stopwatch.ElapsedMilliseconds}ms");
            return privilegedSids;
        }

        private EnrollmentInfo GetTemplateEnrollmentInfo(SearchResult templateResult, Guid[] enrollRightGuids)
        {
            var hasEnroll = false;
            var enrollGroups = new List<string>();
            var excludedAccounts = new List<string>();

            if (templateResult.Properties["nTSecurityDescriptor"].Count > 0)
            {
                try
                {
                    var sdBytes = (byte[])templateResult.Properties["nTSecurityDescriptor"][0];
                    var rawSD = new RawSecurityDescriptor(sdBytes, 0);
                    var dacl = rawSD.DiscretionaryAcl;

                    if (dacl != null)
                    {
                        foreach (var ace in dacl)
                        {
                            if (ace is ObjectAce objAce && objAce.AceType == AceType.AccessAllowedObject)
                            {
                
                                var hasExtendedRight = (objAce.AccessMask & (int)ActiveDirectoryRights.ExtendedRight) == (int)ActiveDirectoryRights.ExtendedRight;
                                
                                if (hasExtendedRight && enrollRightGuids.Contains(objAce.ObjectAceType))
                                {
                                    try
                                    {
                                        var fullGroupName = objAce.SecurityIdentifier.Translate(typeof(NTAccount)).Value;
                                        var group = fullGroupName.Split('\\').Last();
                                        
                                        string? exclusionReason = ShouldExcludeAccountSilent(group, fullGroupName);
                                        if (!string.IsNullOrEmpty(exclusionReason))
                                        {
                                            excludedAccounts.Add($"{fullGroupName} ({exclusionReason})");
                                            continue;
                                        }
                                        
                                        var isPrivilegedByName = IsPrivilegedGroupForTemplate(group);
                                        
                                        var isPrivilegedByGroupMembership = false;
                                        if (!isPrivilegedByName)
                                        {
                                            try
                                            {
                                                AccountType accountType = AdHelper.GetAccountType(group);
                                                
                                                if (accountType == AccountType.User)
                                                {
                                                    var userGroups = GetUserGroupMemberships(group);
                                                    foreach (var userGroup in userGroups)
                                                    {
                                                        if (IsPrivilegedGroupForTemplate(userGroup))
                                                        {
                                                            isPrivilegedByGroupMembership = true;
                                                            excludedAccounts.Add($"{fullGroupName} (belongs to excluded group '{userGroup}')");
                                                            break;
                                                        }
                                                    }
                                                }
                                                else if (accountType == AccountType.Group)
                                                {
                                                }
                                            }
                                            catch (Exception ex)
                                            {
                                                Logger.LogError($"Failed to get group memberships for account '{group}' during enrollment check", ex);
                                            }
                                        }
                                        
                                        if (!isPrivilegedByName && !isPrivilegedByGroupMembership)
                                        {
                                            hasEnroll = true;
                                            enrollGroups.Add(fullGroupName);
                                        }
                                        else if (isPrivilegedByName)
                                        {
                                            excludedAccounts.Add($"{fullGroupName} (in ExcludedGroups list)");
                                        }
                                    }
                                    catch (Exception ex)
                                    {
                                        Logger.LogError($"Error translating SID to account name", ex);
            
                                        if (!Constants.ExcludedGroups.Contains(objAce.SecurityIdentifier.Value))
                                        {
                                            hasEnroll = true;
                                            enrollGroups.Add(objAce.SecurityIdentifier.Value);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    var templateName = templateResult.Properties["displayName"]?[0]?.ToString() ?? "Unknown";
                    Logger.LogError($"Failed to parse template security descriptor for template '{templateName}'", ex);
                    ConsoleHelper.WriteError($"Failed to parse template security descriptor for '{templateName}': {ex.Message}");
                }
            }

            var finalEnrollGroups = enrollGroups.Distinct().ToList();

            return new EnrollmentInfo
            {
                HasEnroll = hasEnroll,
                EnrollmentGroups = finalEnrollGroups,
                ExcludedAccounts = excludedAccounts.Distinct().ToList()
            };
        }

        /// <summary>
        /// Checks if an account should be excluded from vulnerability reporting
        /// Excludes: machine accounts ($), CA server accounts, and accounts in ExcludedAccounts list
        /// </summary>
        private bool ShouldExcludeAccount(string accountName, string? fullAccountName = null)
        {
            return !string.IsNullOrEmpty(ShouldExcludeAccountSilent(accountName, fullAccountName));
        }

        /// <summary>
        /// Checks if an account should be excluded, returning the exclusion reason (or null if not excluded)
        /// This version doesn't log immediately, allowing aggregation of exclusions
        /// </summary>
        private string? ShouldExcludeAccountSilent(string accountName, string? fullAccountName = null)
        {
            if (string.IsNullOrEmpty(accountName))
                return null;

            var normalizedAccount = accountName.ToLower().Trim();
            var fullName = fullAccountName ?? accountName;
            var normalizedFullName = fullName.ToLower().Trim();

            if (fullName.EndsWith("$", StringComparison.OrdinalIgnoreCase))
            {
                return "machine account (ends with $)";
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
                    return $"CA server machine account ({caServer})";
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
                    return "in ExcludedGroups list";
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
                    return "in ExcludedUsers list";
                }
            }

            return null;
        }

        private bool IsPrivilegedGroupForTemplate(string groupName)
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

            if (Constants.ExcludedGroups.Contains(groupName, StringComparer.OrdinalIgnoreCase))
                return true;


            return false;
        }

        private List<string> GetUserGroupMemberships(string username)
        {
            var groups = new List<string>();
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
                catch (Exception)
                {
                    try
                    {
                        var domainEntry = new DirectoryEntry("LDAP://RootDSE");
                        var defaultNC = domainEntry.Properties["defaultNamingContext"][0]?.ToString();
                        var rootEntry = new DirectoryEntry($"LDAP://{defaultNC}");
                        searcher = new DirectorySearcher(rootEntry);
                        Logger.LogInfo("User group lookup LDAP connection method 2: SUCCESS");
                    }
                    catch (Exception)
                    {
                        var domainEntry = new DirectoryEntry();
                        searcher = new DirectorySearcher(domainEntry);
                        Logger.LogInfo("User group lookup LDAP connection method 3: SUCCESS");
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
                        
                        Logger.LogInfo($"Group memberships for user '{username}' retrieved in {stopwatch.ElapsedMilliseconds}ms, found {groups.Count} groups");
                        Core.PerformanceMetrics.IncrementGroupMembershipQuery(false);
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.LogError($"Failed to get group memberships for user '{username}'", ex);
            }

            return groups;
        }

        private Dictionary<string, bool> GetPublishedCertificateTemplates()
        {
            if (_state.CachedTemplates?.IsValid == true)
            {
                Logger.LogInfo("Using cached published certificate templates");
                return _state.CachedTemplates.PublishedTemplates;
            }
            
            var publishedTemplates = new Dictionary<string, bool>();
            
            try
            {
                var stopwatch = System.Diagnostics.Stopwatch.StartNew();
                Logger.LogInfo("Getting published certificate templates from AD...");

                DirectoryEntry? rootDSE = null;
                string? configNC = null;

                Logger.LogInfo("Trying published templates LDAP connection method 1: Machine's domain (fast path)");
                try
                {
                    var machineName = Environment.MachineName;
                    var fqdn = System.Net.Dns.GetHostEntry(machineName).HostName;
                    
                    if (fqdn.Contains("."))
                    {
                        var domain = fqdn.Substring(fqdn.IndexOf(".") + 1);
                        rootDSE = new DirectoryEntry($"LDAP://{domain}/RootDSE", null, null, AuthenticationTypes.Secure);
                        configNC = rootDSE.Properties["configurationNamingContext"]?[0]?.ToString();
                        Logger.LogInfo("Published templates LDAP connection method 1: SUCCESS");
                    }
                }
                catch (Exception ex)
                {
                    Logger.LogError("Published templates LDAP connection method 1 failed", ex);
                    Logger.LogInfo("Published templates LDAP connection method 1: FAILED - Trying method 2: DNS domain lookup");

                    try
                    {
                        var domainName = System.Net.Dns.GetHostEntry(Environment.MachineName).HostName;
                        if (domainName.Contains("."))
                        {
                            domainName = domainName.Substring(domainName.IndexOf(".") + 1);
                            rootDSE = new DirectoryEntry($"LDAP://{domainName}/RootDSE");
                            configNC = rootDSE.Properties["configurationNamingContext"]?[0]?.ToString();
                            Logger.LogInfo("Published templates LDAP connection method 2: SUCCESS");
                        }
                    }
                    catch (Exception ex2)
                    {
                        Logger.LogError("Published templates LDAP connection method 2 failed", ex2);
                        Logger.LogInfo("Published templates LDAP connection method 2: FAILED - Trying method 3: localhost");
    
                        try
                        {
                            rootDSE = new DirectoryEntry("LDAP://localhost/RootDSE");
                            configNC = rootDSE.Properties["configurationNamingContext"]?[0]?.ToString();
                            Logger.LogInfo("Published templates LDAP connection method 3: SUCCESS");
                        }
                        catch (Exception ex3)
                        {
                            Logger.LogError("Published templates LDAP connection method 3 failed", ex3);
                            Logger.LogInfo("Published templates LDAP connection method 3: FAILED - Trying method 4: RootDSE");
        
                            try
                            {
                                rootDSE = new DirectoryEntry("LDAP://RootDSE");
                                configNC = rootDSE.Properties["configurationNamingContext"]?[0]?.ToString();
                                Logger.LogInfo("Published templates LDAP connection method 4: SUCCESS");
                            }
                            catch (Exception ex4)
                            {
                                Logger.LogError("Published templates LDAP connection method 4 failed", ex4);
                                Logger.LogError("Could not connect to any domain controller for published templates", ex4);
                                return publishedTemplates;
                            }
                        }
                    }
                }

                if (string.IsNullOrEmpty(configNC))
                {
                    ConsoleHelper.WriteError("Could not determine configuration naming context.");
                    return publishedTemplates;
                }
                

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

                using var caSearcher = new DirectorySearcher(entry)
                {
                    Filter = "(objectClass=pKIEnrollmentService)",
                    PageSize = 1000,
                    ServerTimeLimit = TimeSpan.FromSeconds(30),
                    ClientTimeout = TimeSpan.FromSeconds(30)
                };
                
                caSearcher.PropertiesToLoad.Add("certificateTemplates");
                
                Logger.LogInfo("Executing LDAP search for published certificate templates...");
                var searchStopwatch = System.Diagnostics.Stopwatch.StartNew();
                var caResults = caSearcher.FindAll();
                searchStopwatch.Stop();
                Logger.LogInfo($"Published templates search completed in {searchStopwatch.ElapsedMilliseconds}ms, found {caResults.Count} CA results");

                foreach (SearchResult ca in caResults)
                {
                    if (ca.Properties["certificateTemplates"].Count > 0)
                    {
                        foreach (string template in ca.Properties["certificateTemplates"])
                        {
                            publishedTemplates[template] = true;
                        }
                    }
                }
                
                stopwatch.Stop();
                Logger.LogInfo($"Published templates retrieved in {stopwatch.ElapsedMilliseconds}ms");
                
                if (_state.CachedTemplates == null)
                    _state.CachedTemplates = new TemplateCache();
                _state.CachedTemplates.PublishedTemplates = publishedTemplates;
                _state.CachedTemplates.CacheTime = DateTime.Now;
            }
            catch (Exception ex)
            {
                Logger.LogError("An error occurred while retrieving published certificate templates from AD configuration", ex);
                ConsoleHelper.WriteError($"An error occurred while retrieving published certificate templates: {ex.Message}");
            }

            return publishedTemplates;
        }

        private SearchResultCollection? GetAllCertificateTemplates()
        {
            Logger.LogInfo("Connecting to AD for certificate template enumeration");
            DirectoryEntry? rootDSE = null;
            string? configNC = null;

            Logger.LogInfo("Trying template LDAP connection method 1: Machine's domain (fast path)");
            try
            {
                var domainName = System.Net.Dns.GetHostEntry(Environment.MachineName).HostName;
                if (domainName.Contains("."))
                {
                    domainName = domainName.Substring(domainName.IndexOf(".") + 1);
                    rootDSE = new DirectoryEntry($"LDAP://{domainName}/RootDSE");
                    configNC = rootDSE.Properties["configurationNamingContext"]?[0]?.ToString();
                    Logger.LogInfo("Template LDAP connection method 1: SUCCESS");
                }
            }
            catch (Exception ex)
            {
                Logger.LogError("Template LDAP connection method 1 failed", ex);
                Logger.LogInfo("Template LDAP connection method 1: FAILED - Trying method 2: localhost");
                try
                {
                    rootDSE = new DirectoryEntry("LDAP://localhost/RootDSE");
                    configNC = rootDSE.Properties["configurationNamingContext"]?[0]?.ToString();
                    Logger.LogInfo("Template LDAP connection method 2: SUCCESS");
                }
                catch (Exception ex2)
                {
                    Logger.LogError("Template LDAP connection method 2 failed", ex2);
                    Logger.LogInfo("Template LDAP connection method 2: FAILED - Trying method 3: Machine FQDN");
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
                            Logger.LogInfo("Template LDAP connection method 3: SUCCESS");
                        }
                    }
                    catch (Exception ex3)
                    {
                        Logger.LogError("Template LDAP connection method 3 failed", ex3);
                        Logger.LogInfo("Template LDAP connection method 3: FAILED - Trying method 4: RootDSE");
                        
                        try
                        {
                            rootDSE = new DirectoryEntry("LDAP://RootDSE");
                            configNC = rootDSE.Properties["configurationNamingContext"]?[0]?.ToString();
                            Logger.LogInfo("Template LDAP connection method 4: SUCCESS");
                        }
                        catch (Exception ex4)
                        {
                            Logger.LogError("Template LDAP connection method 4 failed", ex4);
                            ConsoleHelper.WriteError("Could not connect to any domain controller.");
                            return null;
                        }
                    }
                }
            }
            
            if (string.IsNullOrEmpty(configNC))
            {
                ConsoleHelper.WriteError("Could not determine configuration naming context. Returning empty collection.");
                return null;
            }

            DirectoryEntry entry;
            if (rootDSE?.Path?.Contains("localhost") == true)
            {
                entry = new DirectoryEntry($"LDAP://localhost/CN=Certificate Templates,CN=Public Key Services,CN=Services,{configNC}");
            }
            else if (rootDSE?.Path?.Contains("LDAP://") == true && !rootDSE.Path.Contains("localhost"))
            {
                var domainPart = rootDSE.Path.Replace("/RootDSE", "");
                entry = new DirectoryEntry($"{domainPart}/CN=Certificate Templates,CN=Public Key Services,CN=Services,{configNC}");
            }
            else
            {
                entry = new DirectoryEntry($"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,{configNC}");
            }

            Logger.LogInfo($"Template search base DN: {entry.Path}");
            
            using var searcher = new DirectorySearcher(entry)
            {
                Filter = "(objectClass=pKICertificateTemplate)",
                PageSize = 1000,
                SecurityMasks = SecurityMasks.Dacl,
                ServerTimeLimit = TimeSpan.FromSeconds(30),
                ClientTimeout = TimeSpan.FromSeconds(30)
            };

            searcher.PropertiesToLoad.AddRange(new[] {
                "displayName", "msPKI-Enrollment-Flag", "msPKI-RA-Signature",
                "pKIExtendedKeyUsage", "msPKI-Certificate-Application-Policy",
                "nTSecurityDescriptor", "msPKI-Certificate-Name-Flag",
                "cn", "msPKI-Cert-Template-OID"
            });

            Logger.LogInfo("Executing LDAP search for certificate templates...");
            var searchTimer = System.Diagnostics.Stopwatch.StartNew();
            var results = searcher.FindAll();
            searchTimer.Stop();
            Logger.LogInfo($"Template search completed in {searchTimer.ElapsedMilliseconds}ms, found {results.Count} templates");
            Core.PerformanceMetrics.IncrementLdapQuery(false);
            
            return results;
        }

        private Dictionary<string, TemplateInfo> BuildTemplateLookup(SearchResultCollection results)
        {
            var templateLookup = new Dictionary<string, TemplateInfo>();

            foreach (SearchResult result in results)
            {
                var cn = result.Properties["cn"]?[0]?.ToString();
                var displayName = result.Properties["displayName"]?[0]?.ToString();
                var oid = GetPropertyValue<string>(result, "msPKI-Cert-Template-OID");

                if (string.IsNullOrEmpty(cn) || string.IsNullOrEmpty(displayName))
                {
                    continue;
                }

                var templateObj = new TemplateInfo
                {
                    CN = cn,
                    DisplayName = displayName,
                    OID = oid,
                    Result = result
                };

                templateLookup[cn] = templateObj;
                templateLookup[displayName] = templateObj;
                if (!string.IsNullOrEmpty(oid))
                    templateLookup[oid] = templateObj;
            }

            return templateLookup;
        }



        private T GetPropertyValue<T>(SearchResult result, string propertyName)
        {
            if (result.Properties[propertyName].Count > 0)
            {
                var value = result.Properties[propertyName][0];
                if (value is T directValue)
                    return directValue;
                
                try
                {
                    return (T)Convert.ChangeType(value, typeof(T));
                }
                catch (Exception ex)
                {
                    Logger.LogError($"Error converting value to type {typeof(T).Name}", ex);
                    return default(T)!;
                }
            }
            
            return default(T)!;
        }

        private string? GetUserPrimaryGroup(SearchResult? userResult, DirectorySearcher? searcher)
        {
            try
            {
                if (userResult?.Properties["primaryGroupID"] == null || userResult.Properties["objectSid"] == null)
                    return null;

                var primaryGroupID = Convert.ToInt32(userResult.Properties["primaryGroupID"][0]);
                var userSidBytes = (byte[])userResult.Properties["objectSid"][0];
                var userSid = new SecurityIdentifier(userSidBytes, 0);
                
                var userSidString = userSid.Value;
                var lastHyphenIndex = userSidString.LastIndexOf('-');
                if (lastHyphenIndex < 0)
                    return null;

                var domainSid = userSidString.Substring(0, lastHyphenIndex);
                var primaryGroupSidString = $"{domainSid}-{primaryGroupID}";
                var primaryGroupSid = new SecurityIdentifier(primaryGroupSidString);
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
    }
} 