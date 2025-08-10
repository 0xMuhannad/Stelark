# Stelark Memory Optimization Guide

## Overview
The Stelark tool has been enhanced with memory optimization features to handle environments with 100k+ certificates without running out of memory or crashing the server.

## Key Optimizations Implemented

### 1. Memory Monitoring (`MemoryManager.cs`)
- Real-time memory usage tracking
- Automatic garbage collection when limits are approached
- Memory logging at key checkpoints
- Process memory monitoring in MB

### 2. Streaming Certificate Processing
- `StreamCertutilAsync()` - Processes certificates line-by-line instead of loading all into memory
- Reduces peak memory usage by processing data as it arrives
- Extended timeout (30 minutes) for large datasets
- Periodic memory checks during streaming (every 5000 lines)

### 3. Batch Processing with Limits
- `ProcessCertificatesInBatchesAsync()` - Processes certificates in configurable batches
- Default batch size: 2500 certificates
- Memory checking after each batch
- Early termination if memory limits exceeded

### 4. Configurable Limits and Output
New command-line options:
- `--max-memory <MB>`: Maximum memory usage (default: 2048MB)
- `--batch-size <count>`: Certificates per batch (default: 2500)
- `--max-certs <count>`: Maximum certificates in memory (default: 25,000)
- `--output-dir <path>`: Custom output directory for results and logs (default: ./Stelark)

### 5. Memory-Aware Certificate Collection
- Dynamic memory checking during certutil output collection
- Hard limits on output line collection (prevents infinite memory growth)
- Raw certificate block clearing for older certificates to save memory
- Per-vulnerability-type certificate limits (25% each for ESC1-4)

### 6. Enhanced Output Directory Management
- **Output Directory Validation**: Comprehensive validation of output paths
- **Disk Space Monitoring**: Check available disk space before operations
- **Permission Testing**: Verify write permissions before starting
- **Path Safety**: Prevent writing to files instead of directories

## Usage Examples

### For Large Environments (100k+ certificates)
```bash
# Large memory systems (8GB+ RAM)
Stelark.exe --intense --max-memory 4096 --max-certs 75000

# Medium memory systems (4-8GB RAM)
Stelark.exe --intense --max-memory 2048 --max-certs 50000

# Limited memory systems (<4GB RAM)
Stelark.exe --intense --max-memory 512 --batch-size 1000 --max-certs 10000
```

### Custom Output Directory Examples
```bash
# Run with custom output directory
Stelark.exe --intense --output-dir "C:\SecurityReports\ADCS_Audit"

# Run with memory optimization and custom output
Stelark.exe --intense --max-memory 2048 --output-dir "./results"

# Very conservative settings with custom output
Stelark.exe --intense --max-memory 256 --batch-size 500 --max-certs 5000 --output-dir "/tmp/stelark_scan"
```

## How It Prevents Memory Issues

1. **Early Detection**: Memory usage is checked regularly and logged
2. **Graceful Degradation**: When memory limits are hit, processing stops gracefully rather than crashing
3. **Automatic Cleanup**: Garbage collection is forced when approaching limits
4. **Smart Storage**: Raw certificate blocks are cleared for older certificates
5. **Streaming Processing**: Large datasets are processed incrementally rather than loaded entirely

## Memory Usage Patterns

| Certificate Count | Estimated Memory (Default Settings) | Recommended Settings |
|------------------|-------------------------------------|---------------------|
| < 25,000         | 100-300 MB                          | Default (2GB limit)             |
| 25,000-50,000    | 300-600 MB                         | `--max-memory 2048` (default)  |
| 50,000-100,000   | 600-1200 MB                        | `--max-memory 2048 --max-certs 50000` |
| 100,000-200,000  | 1200-2400 MB                       | `--max-memory 4096 --max-certs 75000` |
| 200,000+         | 2400+ MB                           | `--max-memory 6144 --max-certs 100000` |

## Monitoring and Logging

The tool now provides detailed memory logging:
- Memory usage at startup, completion, and error states
- Batch processing progress with certificate counts
- Memory limit warnings and garbage collection events
- Per-vulnerability-type memory usage tracking

## Backward Compatibility

All existing functionality remains unchanged. The new memory optimizations are:
- Enabled by default with conservative limits
- Fully configurable via command-line options
- Non-breaking for existing scripts and usage patterns

## Emergency Stop Conditions

The tool will gracefully stop processing if:
1. Memory usage exceeds the configured limit (even after garbage collection)
2. Certificate count exceeds the maximum configured limit
3. Certutil output exceeds reasonable size limits
4. Processing timeout is reached (30 minutes for streaming operations)

This ensures the tool never consumes excessive system resources or crashes the host system.

## Implementation Details

### New Classes Added:
- **MemoryManager**: Provides memory monitoring and garbage collection utilities
- **OutputDirectoryValidator**: Validates output paths and checks disk space

### Enhanced Classes:
- **GlobalState**: Added memory-related configuration properties
- **Stelark**: Updated constructors to accept memory parameters
- **CertificateAnalyzer**: Added streaming processing and memory checks
- **Program**: Added command-line argument parsing for memory options

### Key Methods:
- `StreamCertutilAsync()`: Async enumerable for streaming certutil output
- `ProcessCertificatesInBatchesAsync()`: Batch processing with memory limits
- `IsMemoryLimitExceeded()`: Memory monitoring with automatic GC
- `ValidateOutputDirectory()`: Comprehensive output path validation

The implementation maintains full compatibility with the existing codebase while adding robust memory management capabilities for large-scale certificate environments.
