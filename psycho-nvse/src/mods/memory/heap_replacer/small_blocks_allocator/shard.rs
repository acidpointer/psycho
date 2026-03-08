//! Simple shard container

use std::sync::Arc;

use rustc_hash::FxBuildHasher;

type ShardMap<K, V> = clashmap::ClashMap<K, V, FxBuildHasher>;

pub struct ShardPool<K, V> {
    pool: Vec<Shard<K, V>>,
}

impl<K, V> ShardPool<K, V> {
    pub fn new(shards_amount: usize) -> Self {
        debug_assert!(shards_amount.is_multiple_of(2), "Amount of shards MUST be multiple of 2!");
        
        Self {
            pool: (0..shards_amount).map(|_| Shard::new()).collect()
        }
    }

    
    /// Computes which shard should handle a given heap key.
    ///
    /// Uses Fibonacci Hashing to ensure uniform distribution across shards,
    /// even when keys are closely clustered (like aligned pointers).
    #[inline(always)]
    fn get_shard_idx(&self, key: usize) -> usize {
        // 1. Select the Golden Ratio constant based on architecture width
        // 32-bit: (2^32 / phi) = 0x9E3779B9
        // 64-bit: (2^64 / phi) = 0x9E3779B97F4A7C15
        #[cfg(target_pointer_width = "64")]
        const PHI: usize = 0x9e3779b97f4a7c15;

        #[cfg(target_pointer_width = "32")]
        const PHI: usize = 0x9e3779b9;

        // 2. Multiply to spread entropy across the entire word
        let hash = key.wrapping_mul(PHI);

        // 3. Shift and Modulo
        // We use the high bits of the hash as they have the highest entropy
        // after the multiplication.
        // If SHARDS_AMOUNT is a power of 2, the compiler optimizes this to a bit-mask.
        let high_bits = hash >> (usize::BITS as usize / 2);

        high_bits % self.pool.len()
    }

    pub fn get_shard(&self, key: usize) -> &Shard<K, V> {
        let shard_idx = self.get_shard_idx(key);

        &self.pool[shard_idx]
    }

    pub fn get_pool_ref(&self) -> &Vec<Shard<K, V>> {
        &self.pool
    }
}


pub struct Shard<K, V> {
    inner: ShardMap<K, V>,
}

impl<K, V> Shard<K, V> {
    pub fn new() -> Self {
        Self {
            inner: ShardMap::with_hasher(FxBuildHasher),
        }
    }
    
    pub fn get(&self) -> &ShardMap<K, V> {
        &self.inner
    }
}

