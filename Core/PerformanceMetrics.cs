using System;
using System.Collections.Generic;

namespace Stelark.Core
{
    public static class PerformanceMetrics
    {
        private static int _ldapQueries = 0;
        private static int _ldapCacheHits = 0;
        private static int _accountTypeLookups = 0;
        private static int _accountTypeCacheHits = 0;
        private static int _groupMembershipQueries = 0;
        private static int _groupMembershipCacheHits = 0;
        private static int _templatesAnalyzed = 0;
        private static int _templatesVulnerable = 0;
        private static int _templatesSkipped = 0;
        private static int _certificateQueries = 0;
        private static readonly object _lock = new object();

        public static void IncrementLdapQuery(bool fromCache = false)
        {
            lock (_lock)
            {
                _ldapQueries++;
                if (fromCache) _ldapCacheHits++;
            }
        }

        public static void IncrementAccountTypeLookup(bool fromCache = false)
        {
            lock (_lock)
            {
                _accountTypeLookups++;
                if (fromCache) _accountTypeCacheHits++;
            }
        }

        public static void IncrementGroupMembershipQuery(bool fromCache = false)
        {
            lock (_lock)
            {
                _groupMembershipQueries++;
                if (fromCache) _groupMembershipCacheHits++;
            }
        }

        public static void IncrementTemplateAnalyzed(bool isVulnerable = false)
        {
            lock (_lock)
            {
                _templatesAnalyzed++;
                if (isVulnerable)
                    _templatesVulnerable++;
                else
                    _templatesSkipped++;
            }
        }

        public static void IncrementCertificateQuery()
        {
            lock (_lock)
            {
                _certificateQueries++;
            }
        }

        public static void LogPerformanceSummary()
        {
            lock (_lock)
            {
                Services.Logger.LogInfo("=== PERFORMANCE METRICS ===");
                Services.Logger.LogInfo($"LDAP Queries: {_ldapQueries} (Cache hits: {_ldapCacheHits}, Misses: {_ldapQueries - _ldapCacheHits})");
                Services.Logger.LogInfo($"Account Type Lookups: {_accountTypeLookups} (Cached: {_accountTypeCacheHits}, New: {_accountTypeLookups - _accountTypeCacheHits})");
                Services.Logger.LogInfo($"Group Membership Queries: {_groupMembershipQueries} (Cached: {_groupMembershipCacheHits}, Misses: {_groupMembershipQueries - _groupMembershipCacheHits})");
                Services.Logger.LogInfo($"Templates Analyzed: {_templatesAnalyzed} (Vulnerable: {_templatesVulnerable}, Skipped: {_templatesSkipped})");
                Services.Logger.LogInfo($"Certificate Queries: {_certificateQueries}");
                Services.Logger.LogInfo("=== END PERFORMANCE METRICS ===");
            }
        }

        public static void Reset()
        {
            lock (_lock)
            {
                _ldapQueries = 0;
                _ldapCacheHits = 0;
                _accountTypeLookups = 0;
                _accountTypeCacheHits = 0;
                _groupMembershipQueries = 0;
                _groupMembershipCacheHits = 0;
                _templatesAnalyzed = 0;
                _templatesVulnerable = 0;
                _templatesSkipped = 0;
                _certificateQueries = 0;
            }
        }
    }
}

