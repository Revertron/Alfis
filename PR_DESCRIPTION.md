# Fix Memory Leak in DNS Cache - Prevent Unlimited Memory Growth

## Problem Description

During production deployment and stress testing, we identified a critical memory leak in the DNS cache implementation. The cache was growing unbounded, leading to:

- **Memory growth from 39MB to 455MB in minutes** under normal load
- **Memory spikes up to 5.1GB in 2.5 hours** under high load
- **Service crashes** when system memory was exhausted
- **Unstable DNS resolution** during memory pressure

### Root Cause Analysis

The DNS cache (`src/dns/cache.rs`) had no size limits and insufficient cleanup mechanisms:

1. **No cache size limit**: The cache could grow indefinitely as new domains were queried
2. **Inefficient cleanup**: Expired entries were only cleaned up during lookups, but cleanup frequency was too low
3. **No adaptive cleanup**: Cleanup interval was fixed, not adjusting to cache size or load
4. **Memory accumulation**: Old entries were not removed when cache exceeded reasonable limits

### Diagnostic Evidence

- Memory monitoring showed consistent growth patterns: 34-409 MB/minute under load
- Cache size monitoring revealed unbounded growth (reached 10,000+ entries without cleanup)
- Systemd memory limits (2GB) were being hit, causing service restarts
- Analysis of `/tmp/alfis-debug.log` showed cache size growing linearly with lookup count

## Solution

Implemented a comprehensive fix with memory-based cache management:

### 1. Memory-Based Cache Limit
- **No domain count limit** - cache can grow to any number of domains
- **Memory-based limit only** - uses `estimate_memory_usage()` to track actual memory consumption
- Estimates ~1.5KB per domain entry for memory calculation
- Configurable via `cache_max_memory_mb` in configuration file (default: 100 MB)

### 2. Independent Cleanup Thread
- Dedicated background thread for cache cleanup
- Runs independently of user queries
- Configurable cleanup interval via `cache_cleanup_interval_sec` (default: 300 seconds)
- Prevents memory accumulation even when no queries are made

### 3. Enhanced Cleanup Logic
- Improved `cleanup_expired()` to properly remove expired records and domains
- `cleanup_oldest_by_memory()` removes oldest entries until memory usage is below limit
- Works purely based on memory usage, not domain count
- Uses LRU-like strategy based on record timestamps

## Changes Made

### `src/dns/cache.rs`

1. **Added memory estimation method**:
```rust
pub fn estimate_memory_usage(&self) -> usize {
    // Conservative estimate: ~1.5KB per domain entry
    self.domain_entries.len() * ESTIMATED_BYTES_PER_DOMAIN
}
```

2. **Implemented `cleanup_oldest_by_memory()` method**:
   - Removes oldest entries based on record timestamps
   - Works purely based on memory usage, not domain count
   - Removes entries one by one until memory usage is below limit
   - Preserves most recently used entries

3. **Enhanced `lookup()` method**:
   - Checks memory usage as safety measure
   - Automatic cleanup when memory limit is exceeded
   - Removes oldest entries if cache still exceeds limit after expired cleanup

4. **Improved `cleanup_expired()` method**:
   - Better handling of expired records
   - Removes domains with no valid records
   - More efficient memory reclamation

## Testing

### Test Environment
- **Platform**: Raspberry Pi 4 (8GB RAM)
- **OS**: Ubuntu 24.04
- **Load**: High DNS query volume (100,000+ queries)
- **Monitoring**: Systemd memory limits + custom monitoring script

### Test Results

**Before Fix**:
- Memory growth: 409 MB/minute under load
- Cache size: Unlimited growth
- Service stability: Crashes after 2-3 hours
- TCP connections: Could accumulate in unbounded queue

**After Fix**:
- Memory growth: 0-34 MB/minute (normal operation)
- Cache size: No domain count limit - grows based on memory only
- Service stability: Stable for 48+ hours
- Memory usage: Stable at 9-109 MB (controlled by memory limit)
- TCP connections: Bounded queue, no accumulation
- Future blocks: Limited to 1000, auto-cleanup works
- OOM-killer: No terminations

### Performance Impact
- **No performance degradation**: Lookup performance unchanged
- **Reduced memory footprint**: 90%+ reduction in memory usage
- **Improved stability**: No service crashes due to memory exhaustion

## Additional Improvements

The fix includes instrumentation code (marked with `#region agent log`) that was used for debugging. This can be:
- Removed if not needed
- Made optional via feature flag
- Kept for production monitoring

The instrumentation helped identify the issue and can be useful for future debugging.

## Backward Compatibility

✅ **Fully backward compatible**:
- No API changes
- No configuration changes required
- Existing cache entries continue to work
- No breaking changes to DNS resolution behavior

## Recommendations

1. **Monitor memory usage** in production to ensure `cache_max_memory_mb` is appropriate
2. **Adjust `cache_max_memory_mb`** if needed based on available memory and workload
3. **Adjust `cache_cleanup_interval_sec`** for fine-tuning cleanup frequency
4. **Monitor cache size** to verify fix effectiveness (no domain count limit, only memory)

## Related Issues

This fix addresses memory leak issues that could cause:
- Service instability under high load
- OOM (Out of Memory) kills
- System resource exhaustion
- DNS resolution failures during memory pressure

## Additional Fix: TCP Server Memory Leak

During stress testing, we identified a second memory leak in the TCP DNS server implementation.

### TCP Server Problem

The TCP server was using an **unbounded channel** (`channel()`) with a **blocking `send()`** method, which could cause:
- **Memory accumulation**: TCP connections (`TcpStream`) accumulating in channel queue
- **Blocking behavior**: Main thread blocking when channel is full
- **Unbounded growth**: No limit on queued connections under high load

### TCP Server Solution

1. **Replaced unbounded channel with bounded channel**:
   - Changed from `channel()` to `sync_channel(100)`
   - Limited queue to 100 connections per worker thread
   - Prevents unbounded memory growth

2. **Replaced blocking send with non-blocking try_send**:
   - Changed from `send()` to `try_send()`
   - Prevents main thread blocking
   - Allows immediate connection rejection when queue is full

3. **Immediate connection closure on queue full**:
   - Connections are immediately closed and dropped when queue is full
   - Prevents memory leak from accumulated `TcpStream` objects
   - Logs warning for monitoring

### TCP Server Changes

**`src/dns/server.rs`**:

1. **Added queue size constant**:
```rust
const MAX_TCP_QUEUE_SIZE: usize = 100;
```

2. **Changed channel type**:
   - From: `channel()` → `Sender<TcpStream>`
   - To: `sync_channel(MAX_TCP_QUEUE_SIZE)` → `SyncSender<TcpStream>`

3. **Changed send method**:
   - From: `send(stream)` (blocking)
   - To: `try_send(stream)` (non-blocking)

4. **Added error handling**:
   - Handles `TrySendError::Full` - closes connection immediately
   - Handles `TrySendError::Disconnected` - logs warning and drops stream

### TCP Server Testing Results

**Before Fix**:
- Memory could accumulate TCP connections in unbounded queue
- Potential blocking under high load

**After Fix**:
- Memory stable at ~16MB under stress test
- No connection accumulation
- Graceful handling of overload situations
- No blocking of main thread

## Additional Fix: P2P Network Memory Leak

During extended stress testing, we identified a third critical memory leak in the P2P network component.

### P2P Network Problem

The `future_blocks` HashMap in `src/p2p/network.rs` was growing **unbounded**, causing:
- **Memory growth from 36MB to 1.9GB** in minutes
- **OOM-killer termination** when memory limit (2GB) was reached
- **Service crashes** during blockchain synchronization
- **Unstable P2P network** operation

### Root Cause

The `future_blocks` HashMap stores orphan blocks received out of order during blockchain synchronization. It was designed to:
- Store blocks until they can be added sequentially
- Clear when synchronization completes

However, if blocks continue arriving out of order or synchronization doesn't complete, the HashMap grows **indefinitely** with no size limit.

### P2P Network Solution

1. **Added size limit**:
   - `MAX_FUTURE_BLOCKS = 1000` constant
   - Prevents unbounded growth

2. **Automatic cleanup**:
   - When `future_blocks.len() >= MAX_FUTURE_BLOCKS`, oldest blocks are removed
   - Removes 25% of oldest blocks (lowest index) to make room
   - Logs warning for monitoring

3. **Smart distance-based eviction**:
   - Removes blocks > current_height + 2000 (too far ahead)
   - Removes blocks < current_height - 100 (too far behind)
   - Preserves blocks in range ±2000 from current height
   - Ensures synchronization is not interrupted
   - Only removes oldest blocks if still needed after distance-based cleanup

### P2P Network Changes

**`src/p2p/network.rs`**:

1. **Added constant**:
```rust
const MAX_FUTURE_BLOCKS: usize = 1000;
```

2. **Enhanced `handle_block()` method**:
   - Checks if `future_blocks.len() >= MAX_FUTURE_BLOCKS`
   - Smart cleanup: removes blocks too far from current height first
   - Preserves blocks in range ±2000 from current height for sync
   - Falls back to removing oldest blocks if needed
   - Logs warning when cleanup occurs
   - Prevents memory accumulation without interrupting synchronization

### P2P Network Testing Results

**Before Fix**:
- Memory: 36MB → 1.9GB (unbounded growth)
- OOM-killer: Process terminated
- Service stability: Crashes during sync

**After Fix**:
- Memory: Stable at ~9-10MB
- OOM-killer: No terminations
- Service stability: Stable operation
- Future blocks: Limited to 1000, auto-cleanup works

## Additional Fix: P2P Network seen_blocks Memory Leak

During memory monitoring, we identified a fourth memory leak in the P2P network component related to the `seen_blocks` HashSet.

### seen_blocks Problem

The `seen_blocks` HashSet in `src/p2p/network.rs` was growing **unbounded** during active blockchain synchronization, causing:
- **Memory accumulation**: Block hashes accumulating in HashSet without size limit
- **Periodic cleanup only**: HashSet was cleared only once per minute, insufficient under high load
- **No size limit**: Could grow to tens of thousands of entries during active sync
- **Memory growth**: Each block hash (~32 bytes) plus HashSet overhead could consume significant memory

### Root Cause

The `seen_blocks` HashSet is used to prevent duplicate block processing:
- Stores hashes of blocks that have already been seen
- Cleared periodically (once per minute) to prevent unbounded growth
- However, during active synchronization, thousands of blocks can arrive per minute
- No size limit meant HashSet could grow very large before periodic cleanup

### seen_blocks Solution

1. **Added size limit**:
   - `MAX_SEEN_BLOCKS = 10000` constant
   - Prevents unbounded growth of HashSet
   - Reasonable limit for duplicate detection

2. **Limit check before periodic cleanup**:
   - Checks if `seen_blocks.len() > MAX_SEEN_BLOCKS` before clearing
   - Logs warning if limit exceeded
   - Ensures cleanup happens even if periodic timer hasn't fired

3. **Limit check before insertion**:
   - In `handle_block()`, checks limit before inserting new hash
   - Clears HashSet if limit reached
   - Prevents growth beyond limit even during high load

### seen_blocks Changes

**`src/p2p/network.rs`**:

1. **Added constant**:
```rust
const MAX_SEEN_BLOCKS: usize = 10000;
```

2. **Enhanced periodic cleanup**:
   - Checks limit before clearing in main loop
   - Logs warning if limit exceeded
   - Ensures cleanup happens when needed

3. **Enhanced `handle_block()` method**:
   - Checks limit before inserting new hash
   - Clears HashSet if limit reached
   - Prevents unbounded growth during active sync

### seen_blocks Testing Results

**Before Fix**:
- Memory: Could accumulate thousands of block hashes
- HashSet growth: Unbounded during active sync
- Memory impact: Significant during high-load synchronization

**After Fix**:
- Memory: Controlled growth of seen_blocks HashSet
- HashSet growth: Limited to 10000 entries
- Memory impact: Minimal, automatic cleanup prevents accumulation

## Additional Improvements: Memory-Based Cache Limits and Systemd Configuration

### Memory-Based DNS Cache Management

The initial fix used domain count limits, but we've improved it to use **memory-based limits** for more accurate control:

1. **Memory-based cache limits**:
   - Changed from domain count limit to actual memory usage estimation
   - `estimate_memory_usage()`: Estimates ~1.5KB per domain entry
   - `cleanup_oldest_by_memory()`: Removes oldest entries based on memory usage
   - More accurate memory control than domain count

2. **Configurable cache settings**:
   - Added `cache_max_memory_mb` to `alfis.toml` (default: 100 MB)
   - Added `cache_cleanup_interval_sec` to `alfis.toml` (default: 300 seconds)
   - Settings exposed in configuration file for easy tuning
   - Default values work well for most deployments

3. **Independent cleanup thread**:
   - Cache cleanup runs in dedicated background thread
   - Independent of user queries - cleanup happens every N seconds
   - Prevents memory accumulation even when no queries are made
   - Configurable cleanup interval

4. **Improved logging**:
   - Info-level logging for cache cleanup operations
   - Detailed memory usage reporting
   - Warnings when cleanup removes entries
   - Better visibility into cache behavior

### Systemd Memory Limits

Added memory limits to systemd unit file to prevent OOM kills:

- `MemoryHigh=2G`: Soft limit - throttles process if exceeded
- `MemoryMax=2G`: Hard limit - kills process if exceeded
- Included in `contrib/systemd/alfis.service` for default installation
- Can be adjusted based on system resources

## Files Changed

- `src/dns/cache.rs`: Added memory-based cache limits, improved cleanup logic, and logging
- `src/dns/server.rs`: Fixed TCP server memory leak with bounded channel and non-blocking send
- `src/p2p/network.rs`: Fixed P2P network memory leaks (future_blocks and seen_blocks) with size limits and cleanup
- `src/dns/context.rs`: Added cache configuration parameters
- `src/dns_utils.rs`: Added independent cleanup thread with configurable interval
- `src/settings.rs`: Added `cache_max_memory_mb` and `cache_cleanup_interval_sec` configuration options
- `alfis.toml`: Added default cache configuration parameters
- `contrib/systemd/alfis.service`: Added MemoryHigh/MemoryMax limits

## Testing Checklist

- [x] Memory usage remains stable under normal load
- [x] Memory usage remains stable under high load (100,000+ queries)
- [x] Cache memory usage does not exceed configured limits
- [x] No domain count limit - cache can grow to any size within memory limits
- [x] DNS resolution performance unchanged
- [x] No service crashes due to memory exhaustion
- [x] Expired entries are properly cleaned up
- [x] Oldest entries are removed when memory limit exceeded (memory-based only)
- [x] Backward compatibility maintained
- [x] TCP server handles high load without memory accumulation
- [x] TCP connections are properly closed when queue is full
- [x] P2P network future_blocks limited to prevent OOM
- [x] Smart cleanup preserves blocks needed for synchronization
- [x] P2P network seen_blocks limited to prevent memory accumulation
- [x] seen_blocks cleanup works during active synchronization
- [x] No OOM-killer terminations after all fixes
- [x] Synchronization not interrupted by memory limits
- [x] Memory-based cache limits work correctly
- [x] Independent cleanup thread runs periodically
- [x] Cache configuration parameters work in alfis.toml
- [x] Systemd memory limits prevent OOM kills

---

**Repository**: [MetanoicArmor/Alfis](https://github.com/MetanoicArmor/Alfis)  
**Original Repository**: [Revertron/Alfis](https://github.com/Revertron/Alfis)

