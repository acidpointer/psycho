//! `EventEmitter` implementation for Rust
//! 
//! We have Node.js like EventEmitter inside game hacking library,
//! so you can subscribe to events or emit them, while dealing
//! with addresses relocation.

use dashmap::DashMap;
use parking_lot::RwLock;
use std::hash::Hash;
use std::sync::Arc;

pub type ListenerId = u128;

/// Event listener
/// 
/// Represents event listener callback and it's id.
/// 
/// # Safety
/// Safe, because inner callback stored in Arc and have same lifetime as EventEmitter
#[derive(Clone)]
pub struct Listener<'a, P: Send + Sync> {
    id: ListenerId,
    callback: Arc<dyn Fn(&P) + Send + Sync +'a>,
}

impl<'a, P: Send + Sync> Listener<'a, P> {
    fn new<F: Fn(&P) + Send + Sync + 'a>(id: ListenerId, callback: F) -> Self {
        Self {
            id,
            callback: Arc::new(callback),
        }   
    }

    /// Returns id of current listener
    pub fn get_id(&self) -> ListenerId {
        self.id
    }
}

/// EventEmitter
/// 
/// Inspired by EventEmitter in Node.JS  
/// Each event emitter will work only with one type of callback payload
/// and event.  
/// 
/// Best practices: use emitter as event system under the hood of higher
/// level abstraction.
/// 
/// # Safety
/// Listeners stored in concurrent hash map - `DashMap`.  
/// Callback and payload needs to be `Send` + `Sync`.
pub struct EventEmitter<'a, E: Send + Sync + Copy + Clone + Eq + Hash, P: Send + Sync> {
    last_id: RwLock<ListenerId>,

    /// We store listeners in nested hashmap.
    /// DashMap is quite good for such type of task, because
    /// it offers built-in concurrency support and already
    /// correctly implements needed synchronizations under the hood.
    listeners: DashMap<E, DashMap<ListenerId, Listener<'a, P>>>,
}

impl<'a, E: Send + Sync + Copy + Clone + Eq + Hash, P: Send + Sync> Default for EventEmitter<'a, E, P> {
    fn default() -> Self {
        Self {
            last_id: Default::default(),
            listeners: Default::default(),
        }
    }
}

impl<'a, E: Send + Sync + Copy + Clone + Eq + Hash, P: Send + Sync> EventEmitter<'a, E, P> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create new listener and returns it id.
    /// Simple explanation: callback will be executed on each emit of 'event'
    pub fn on<F: Fn(&P) + Send + Sync + 'a>(&self, event: E, callback: F) -> ListenerId {
        let mut listener_id = self.last_id.write();

        let listener = Listener::new(*listener_id, callback);


        if let Some(listeners) = self.listeners.get_mut(&event) {
            listeners.insert(*listener_id, listener);
        } else {
            let map = DashMap::new();
            map.insert(*listener_id, listener);

            self.listeners.insert(event, map);
        }

        *listener_id +=1;


        *listener_id
    }

    /// Remove listener from EventEmitter by listener id
    pub fn off(&self, listener_id: ListenerId) -> bool {
        for all_listeners in self.listeners.iter() {
            match all_listeners.remove(&listener_id) {
                Some((_listener_id, _listener)) => { return true },
                None => { continue }
            }
        }

        false
    }

    /// Emits event in EventEmitter, passing some payload to it.
    /// All subscribed listeners will execute it's callbacks with non-mut ref
    /// to payload
    pub fn emit(&self, event: E, payload: P) {
        let listeners_for_event = match self.listeners.get(&event) {
            Some(listeners) => listeners,
            None => return,
        };


        for listener in listeners_for_event.iter() {
            (listener.callback)(&payload);
        }
    }
}
