using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Threading;
using Stelark.Models;

namespace Stelark.Services
{
    /// <summary>
    /// High-performance object pooling service to reduce garbage collection pressure
    /// </summary>
    public static class ObjectPooling
    {
        /// <summary>
        /// Generic object pool interface
        /// </summary>
        public interface IObjectPool<T> where T : class
        {
            T Rent();
            void Return(T item);
            int Count { get; }
        }

        /// <summary>
        /// High-performance concurrent object pool implementation
        /// </summary>
        public class ConcurrentObjectPool<T> : IObjectPool<T> where T : class, new()
        {
            private readonly ConcurrentBag<T> _pool;
            private readonly Func<T> _factory;
            private readonly Action<T>? _resetAction;
            private readonly int _maxSize;
            private int _currentCount;

            public ConcurrentObjectPool(int maxSize = 1000, Func<T>? factory = null, Action<T>? resetAction = null)
            {
                _pool = new ConcurrentBag<T>();
                _factory = factory ?? (() => new T());
                _resetAction = resetAction;
                _maxSize = maxSize;
                _currentCount = 0;
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public T Rent()
            {
                if (_pool.TryTake(out var item))
                {
                    Interlocked.Decrement(ref _currentCount);
                    return item;
                }

                return _factory();
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public void Return(T item)
            {
                if (item == null) return;

                // Reset object state if reset action is provided
                _resetAction?.Invoke(item);

                // Only return to pool if we haven't exceeded max size
                if (_currentCount < _maxSize)
                {
                    _pool.Add(item);
                    Interlocked.Increment(ref _currentCount);
                }
                // Otherwise let GC handle it
            }

            public int Count => _currentCount;
        }

        /// <summary>
        /// Certificate-specific object pool with optimized reset logic
        /// </summary>
        public static class CertificatePool
        {
            private static readonly ConcurrentObjectPool<Certificate> _pool =
                new(maxSize: 5000, resetAction: ResetCertificate);

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public static Certificate Rent()
            {
                return _pool.Rent();
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public static void Return(Certificate certificate)
            {
                _pool.Return(certificate);
            }

            public static int Count => _pool.Count;

            /// <summary>
            /// Reset certificate object to default state for reuse
            /// </summary>
            private static void ResetCertificate(Certificate cert)
            {
                cert.Reset();
            }
        }

        /// <summary>
        /// String list pool for reducing allocations in parsing operations
        /// </summary>
        public static class StringListPool
        {
            private static readonly ConcurrentObjectPool<List<string>> _pool =
                new(maxSize: 1000, resetAction: list => list.Clear());

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public static List<string> Rent()
            {
                return _pool.Rent();
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public static void Return(List<string> list)
            {
                _pool.Return(list);
            }

            public static int Count => _pool.Count;
        }

        /// <summary>
        /// Disposable wrapper for automatic return to pool
        /// </summary>
        public struct PooledObject<T> : IDisposable where T : class
        {
            private readonly IObjectPool<T> _pool;
            private T? _object;

            public PooledObject(IObjectPool<T> pool)
            {
                _pool = pool;
                _object = pool.Rent();
            }

            public T Value => _object ?? throw new ObjectDisposedException(nameof(PooledObject<T>));

            public void Dispose()
            {
                if (_object != null)
                {
                    _pool.Return(_object);
                    _object = null;
                }
            }
        }
    }

    /// <summary>
    /// Pool statistics and monitoring
    /// </summary>
    public static class PoolStatistics
    {
        public static void LogPoolStatistics()
        {
            Logger.LogInfo($"Object Pool Statistics:");
            Logger.LogInfo($"  Certificate Pool: {ObjectPooling.CertificatePool.Count} objects");
            Logger.LogInfo($"  String List Pool: {ObjectPooling.StringListPool.Count} objects");
        }

        public static void WarmUpPools()
        {
            // Pre-populate pools with some objects for immediate availability
            var certificates = new List<Certificate>();
            var stringLists = new List<List<string>>();

            // Rent and immediately return objects to warm up the pools
            for (int i = 0; i < 100; i++)
            {
                certificates.Add(ObjectPooling.CertificatePool.Rent());
                stringLists.Add(ObjectPooling.StringListPool.Rent());
            }

            foreach (var cert in certificates) ObjectPooling.CertificatePool.Return(cert);
            foreach (var list in stringLists) ObjectPooling.StringListPool.Return(list);

            Logger.LogInfo("Object pools warmed up successfully");
        }
    }
}