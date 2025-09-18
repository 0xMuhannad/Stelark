using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Stelark.Helpers
{
    /// <summary>
    /// Advanced performance optimization algorithms including Boyer-Moore string matching
    /// </summary>
    public static class PerformanceOptimizations
    {
        /// <summary>
        /// Boyer-Moore string matcher for high-performance pattern searching
        /// </summary>
        public class BoyerMooreMatcher
        {
            private readonly string _pattern;
            private readonly int[] _badCharTable;
            private readonly int[] _goodSuffixTable;

            public BoyerMooreMatcher(string pattern)
            {
                _pattern = pattern ?? throw new ArgumentNullException(nameof(pattern));
                _badCharTable = BuildBadCharTable(_pattern);
                _goodSuffixTable = BuildGoodSuffixTable(_pattern);
            }

            /// <summary>
            /// Search for pattern in text using Boyer-Moore algorithm
            /// </summary>
            /// <param name="text">Text to search in</param>
            /// <returns>Index of first match, -1 if not found</returns>
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public int Match(ReadOnlySpan<char> text)
            {
                if (_pattern.Length > text.Length)
                    return -1;

                int textIndex = _pattern.Length - 1;

                while (textIndex < text.Length)
                {
                    int patternIndex = _pattern.Length - 1;
                    int currentTextIndex = textIndex;

                    // Compare from right to left
                    while (patternIndex >= 0 && _pattern[patternIndex] == text[currentTextIndex])
                    {
                        patternIndex--;
                        currentTextIndex--;
                    }

                    if (patternIndex < 0)
                    {
                        // Match found
                        return currentTextIndex + 1;
                    }

                    // Calculate shift using bad character and good suffix heuristics
                    int badCharShift = _badCharTable[text[currentTextIndex]] - (_pattern.Length - 1 - patternIndex);
                    int goodSuffixShift = _goodSuffixTable[patternIndex];

                    textIndex += Math.Max(badCharShift, goodSuffixShift);
                }

                return -1;
            }

            /// <summary>
            /// Build bad character table for Boyer-Moore algorithm
            /// </summary>
            private static int[] BuildBadCharTable(string pattern)
            {
                var table = new int[65536]; // Cover full Unicode BMP

                // Initialize all characters to pattern length
                for (int i = 0; i < table.Length; i++)
                {
                    table[i] = pattern.Length;
                }

                // Set actual character positions
                for (int i = 0; i < pattern.Length - 1; i++)
                {
                    table[pattern[i]] = pattern.Length - 1 - i;
                }

                return table;
            }

            /// <summary>
            /// Build good suffix table for Boyer-Moore algorithm
            /// </summary>
            private static int[] BuildGoodSuffixTable(string pattern)
            {
                int m = pattern.Length;
                var table = new int[m];
                var borderTable = new int[m + 1];

                // Build border table
                borderTable[m] = m + 1;
                int i = m, j = m + 1;

                while (i > 0)
                {
                    while (j <= m && pattern[i - 1] != pattern[j - 1])
                    {
                        if (table[j - 1] == 0)
                            table[j - 1] = j - i;
                        j = borderTable[j];
                    }
                    i--; j--;
                    borderTable[i] = j;
                }

                // Fill remaining entries
                j = borderTable[0];
                for (i = 0; i < m; i++)
                {
                    if (table[i] == 0)
                        table[i] = j;
                    if (i == j)
                        j = borderTable[j];
                }

                return table;
            }
        }

        /// <summary>
        /// Pre-compiled Boyer-Moore matchers for common SAN patterns
        /// </summary>
        public static class SANMatchers
        {
            public static readonly BoyerMooreMatcher UPNMatcher = new("SAN:upn=");
            public static readonly BoyerMooreMatcher DNSMatcher = new("SAN:dns=");
            public static readonly BoyerMooreMatcher RFC822Matcher = new("SAN:rfc822Name=");
            public static readonly BoyerMooreMatcher GenericUPNMatcher = new("upn=");

            /// <summary>
            /// Fast SAN detection using Boyer-Moore algorithm
            /// </summary>
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public static bool HasSANInBlock(ReadOnlySpan<char> text)
            {
                return UPNMatcher.Match(text) >= 0 ||
                       DNSMatcher.Match(text) >= 0 ||
                       RFC822Matcher.Match(text) >= 0 ||
                       GenericUPNMatcher.Match(text) >= 0;
            }

            /// <summary>
            /// Extract UPN from SAN using fast pattern matching
            /// </summary>
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public static string? ExtractUPN(ReadOnlySpan<char> text)
            {
                var upnIndex = UPNMatcher.Match(text);
                if (upnIndex >= 0)
                {
                    var startIndex = upnIndex + "SAN:upn=".Length;
                    if (startIndex < text.Length)
                    {
                        var remainingText = text.Slice(startIndex);
                        var endIndex = remainingText.IndexOfAny(new char[] { '\r', '\n', ' ', ',', '"' });
                        return endIndex >= 0 ? remainingText.Slice(0, endIndex).ToString() : remainingText.ToString();
                    }
                }

                var genericIndex = GenericUPNMatcher.Match(text);
                if (genericIndex >= 0)
                {
                    var startIndex = genericIndex + "upn=".Length;
                    if (startIndex < text.Length)
                    {
                        var remainingText = text.Slice(startIndex);
                        var endIndex = remainingText.IndexOfAny(new char[] { '\r', '\n', ' ', ',', '"' });
                        return endIndex >= 0 ? remainingText.Slice(0, endIndex).ToString() : remainingText.ToString();
                    }
                }

                return null;
            }
        }

        /// <summary>
        /// Memory-efficient string operations
        /// </summary>
        public static class StringOptimizations
        {
            /// <summary>
            /// Fast string joining without unnecessary allocations
            /// </summary>
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public static string JoinOptimized(IEnumerable<string> values, char separator)
            {
                return string.Join(separator, values);
            }

            /// <summary>
            /// Fast substring extraction with bounds checking
            /// </summary>
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public static ReadOnlySpan<char> SafeSlice(ReadOnlySpan<char> source, int start, int length)
            {
                if (start >= source.Length) return ReadOnlySpan<char>.Empty;
                if (start + length > source.Length) length = source.Length - start;
                return source.Slice(start, Math.Max(0, length));
            }

            /// <summary>
            /// Fast case-insensitive comparison
            /// </summary>
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public static bool EqualsIgnoreCase(ReadOnlySpan<char> left, ReadOnlySpan<char> right)
            {
                return left.Equals(right, StringComparison.OrdinalIgnoreCase);
            }
        }

        /// <summary>
        /// Optimized collection operations
        /// </summary>
        public static class CollectionOptimizations
        {
            /// <summary>
            /// Pre-size collections based on estimated capacity
            /// </summary>
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public static List<T> CreateOptimizedList<T>(int estimatedCapacity)
            {
                return new List<T>(Math.Max(16, estimatedCapacity));
            }

            /// <summary>
            /// Pre-size dictionaries based on estimated capacity
            /// </summary>
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public static Dictionary<TKey, TValue> CreateOptimizedDictionary<TKey, TValue>(int estimatedCapacity)
                where TKey : notnull
            {
                return new Dictionary<TKey, TValue>(Math.Max(16, estimatedCapacity));
            }

            /// <summary>
            /// Fast batch addition to lists
            /// </summary>
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public static void AddRangeFast<T>(List<T> target, IEnumerable<T> source)
            {
                if (source is ICollection<T> collection)
                {
                    target.EnsureCapacity(target.Count + collection.Count);
                }
                target.AddRange(source);
            }
        }

        /// <summary>
        /// Warm up performance-critical code paths
        /// </summary>
        public static void WarmUpOptimizations()
        {
            // Warm up Boyer-Moore matchers
            var testText = "Sample SAN:upn=test@domain.com for warmup".AsSpan();
            SANMatchers.HasSANInBlock(testText);
            SANMatchers.ExtractUPN(testText);

            // Warm up collection optimizations
            var testList = CollectionOptimizations.CreateOptimizedList<string>(100);
            var testDict = CollectionOptimizations.CreateOptimizedDictionary<string, string>(100);

            // Force JIT compilation of critical paths
            GC.Collect(0, GCCollectionMode.Optimized);
            GC.WaitForPendingFinalizers();
        }
    }
}