using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Stelark.Models;

namespace Stelark.Services
{
    /// <summary>
    /// Optimizes database queries by batching multiple template searches into single queries
    /// </summary>
    public static class QueryBatcher
    {
        private const int MaxBatchSize = 50; // Limit OR conditions to prevent query complexity issues
        private const string RequiredColumns = "RequestID,RequesterName,CertificateTemplate,RequestDispositionMessage,RequestSubmissionDate,CertificateEffectiveDate,CertificateExpirationDate,SerialNumber,CertificateHash";

        /// <summary>
        /// Execute batched queries for multiple templates using OR conditions
        /// </summary>
        /// <param name="templates">Templates to query</param>
        /// <param name="executeQuery">Function to execute the actual certutil query</param>
        /// <returns>Combined results from all batched queries</returns>
        public static async Task<List<string>> ExecuteBatchedQueriesAsync(
            List<VulnerableTemplate> templates,
            Func<string, Task<List<string>>> executeQuery)
        {
            var allResults = new List<string>();
            var templateBatches = CreateTemplateBatches(templates);

            Logger.LogInfo($"Executing {templateBatches.Count} batched queries for {templates.Count} templates");

            foreach (var batch in templateBatches)
            {
                try
                {
                    var batchQuery = BuildBatchQuery(batch);
                    var batchResults = await executeQuery(batchQuery);
                    allResults.AddRange(batchResults);

                    Logger.LogInfo($"Batch query completed: {batch.Count} templates, {batchResults.Count} results");
                }
                catch (Exception ex)
                {
                    Logger.LogError($"Batch query failed for {batch.Count} templates", ex);

                    // Fallback to individual queries for this batch
                    var fallbackResults = await ExecuteFallbackQueries(batch, executeQuery);
                    allResults.AddRange(fallbackResults);
                }
            }

            return allResults;
        }

        /// <summary>
        /// Create optimized batches of templates for querying
        /// </summary>
        private static List<List<VulnerableTemplate>> CreateTemplateBatches(List<VulnerableTemplate> templates)
        {
            var batches = new List<List<VulnerableTemplate>>();

            for (int i = 0; i < templates.Count; i += MaxBatchSize)
            {
                var batch = templates.Skip(i).Take(MaxBatchSize).ToList();
                batches.Add(batch);
            }

            return batches;
        }

        /// <summary>
        /// Build a single query with OR conditions for multiple templates
        /// </summary>
        private static string BuildBatchQuery(List<VulnerableTemplate> templates)
        {
            var orConditions = new List<string>();

            foreach (var template in templates)
            {
                // Add conditions for DisplayName, CN, and OID
                if (!string.IsNullOrEmpty(template.DisplayName))
                {
                    orConditions.Add($"CertificateTemplate={template.DisplayName}");
                }

                if (!string.IsNullOrEmpty(template.CN) && template.CN != template.DisplayName)
                {
                    orConditions.Add($"CertificateTemplate={template.CN}");
                }

                if (!string.IsNullOrEmpty(template.OID))
                {
                    orConditions.Add($"CertificateTemplate={template.OID}");
                }
            }

            // Build the restriction with OR conditions
            var restriction = string.Join(" OR ", orConditions.Distinct());
            return $"-view -restrict \"{restriction}\" -out {RequiredColumns} csv";
        }

        /// <summary>
        /// Fallback to individual queries when batch query fails
        /// </summary>
        private static async Task<List<string>> ExecuteFallbackQueries(
            List<VulnerableTemplate> templates,
            Func<string, Task<List<string>>> executeQuery)
        {
            var allResults = new List<string>();

            Logger.LogWarning($"Falling back to individual queries for {templates.Count} templates");

            foreach (var template in templates)
            {
                try
                {
                    var individualQuery = $"-view -restrict \"CertificateTemplate={template.DisplayName}\" -out {RequiredColumns} csv";
                    var results = await executeQuery(individualQuery);
                    allResults.AddRange(results);
                }
                catch (Exception ex)
                {
                    Logger.LogError($"Individual fallback query failed for template {template.DisplayName}", ex);
                }
            }

            return allResults;
        }

        /// <summary>
        /// Execute a single optimized batch query for all templates of a vulnerability type
        /// </summary>
        /// <param name="templates">All templates for the vulnerability type</param>
        /// <param name="executeQuery">Function to execute certutil queries</param>
        /// <returns>All certificates found across templates</returns>
        public static async Task<List<string>> ExecuteSingleBatchQueryAsync(
            List<VulnerableTemplate> templates,
            Func<string, Task<List<string>>> executeQuery)
        {
            if (!templates.Any())
                return new List<string>();

            try
            {
                // For small template counts, use a single query
                if (templates.Count <= MaxBatchSize)
                {
                    var singleQuery = BuildBatchQuery(templates);
                    var results = await executeQuery(singleQuery);

                    Logger.LogInfo($"Single batch query executed for {templates.Count} templates, {results.Count} results");
                    return results;
                }
                else
                {
                    // For large template counts, use batched approach
                    return await ExecuteBatchedQueriesAsync(templates, executeQuery);
                }
            }
            catch (Exception ex)
            {
                Logger.LogError($"Batch query optimization failed for {templates.Count} templates", ex);

                // Final fallback to original sequential approach would be handled by caller
                throw;
            }
        }

        /// <summary>
        /// Calculate optimal batch size based on query complexity and system resources
        /// </summary>
        public static int CalculateOptimalBatchSize(int templateCount, long availableMemoryMB)
        {
            // Adjust batch size based on available memory and template count
            var memoryBasedSize = (int)(availableMemoryMB / 100); // Rough heuristic
            var templateBasedSize = Math.Min(templateCount / 4, MaxBatchSize); // Quarter of templates per batch max

            return Math.Min(Math.Max(10, Math.Min(memoryBasedSize, templateBasedSize)), MaxBatchSize);
        }
    }
}