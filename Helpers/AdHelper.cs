using System;
using System.Collections.Generic;
using System.DirectoryServices;
using Stelark.Core;
using Stelark.Services;

namespace Stelark.Helpers
{
    public enum AccountType
    {
        User,
        Group,
        Unknown
    }

    public static class AdHelper
    {
        private static readonly Dictionary<string, AccountType> _accountTypeCache = new Dictionary<string, AccountType>(StringComparer.OrdinalIgnoreCase);

        public static AccountType GetAccountType(string accountName)
        {
            if (string.IsNullOrEmpty(accountName))
                return AccountType.Unknown;

            if (_accountTypeCache.TryGetValue(accountName, out var cachedType))
            {
                Core.PerformanceMetrics.IncrementAccountTypeLookup(true);
                return cachedType;
            }

            AccountType type = AccountType.Unknown;
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
                    }
                    catch (Exception)
                    {
                        var domainEntry = new DirectoryEntry();
                        searcher = new DirectorySearcher(domainEntry);
                    }
                }

                if (searcher != null)
                {
                    using (searcher)
                    {
                        searcher.Filter = $"(&(objectClass=user)(sAMAccountName={accountName}))";
                        searcher.PropertiesToLoad.Clear();
                        searcher.PropertiesToLoad.Add("objectClass");
                        searcher.ServerTimeLimit = TimeSpan.FromSeconds(10);
                        searcher.ClientTimeout = TimeSpan.FromSeconds(10);
                        
                        var userResult = searcher.FindOne();
                        if (userResult != null)
                        {
                            type = AccountType.User;
                        }
                        else
                        {
                            searcher.Filter = $"(&(objectClass=group)(sAMAccountName={accountName}))";
                            var groupResult = searcher.FindOne();
                            if (groupResult != null)
                            {
                                type = AccountType.Group;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.LogError($"Failed to determine account type for '{accountName}'", ex);
            }

            _accountTypeCache[accountName] = type;
            Core.PerformanceMetrics.IncrementAccountTypeLookup(false);
            if (type != AccountType.Unknown)
            {
                Logger.LogInfo($"Account type determined for '{accountName}': {type}");
            }
            return type;
        }
    }
}

