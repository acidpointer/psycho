//! `EventEmitter` implementation for Rust
//!
//! We have Node.js like EventEmitter inside game hacking library,
//! so you can subscribe to events or emit them, while dealing
//! with addresses relocation.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;

pub type ListenerId = u128;

/// Event listener
///
/// Represents event listener callback and it's id.
///
/// # Safety
/// Safe, because inner callback stored in Arc and have same lifetime as EventEmitter
pub struct Listener<'a, P: Send + Sync> {
    id: ListenerId,
    callback: Arc<dyn Fn(&P) + Send + Sync + 'a>,
}

impl<P: Send + Sync> Clone for Listener<'_, P> {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            callback: Arc::clone(&self.callback),
        }
    }
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

    listeners: RwLock<HashMap<E, HashMap<ListenerId, Listener<'a, P>>>>,
}

impl<'a, E: Send + Sync + Copy + Clone + Eq + Hash, P: Send + Sync> Default
    for EventEmitter<'a, E, P>
{
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

        let id = *listener_id;
        let listener = Listener::new(id, callback);
        let mut listeners = self.listeners.write();

        listeners.entry(event).or_default().insert(id, listener);

        *listener_id += 1;

        id
    }

    /// Remove listener from EventEmitter by listener id
    pub fn off(&self, listener_id: ListenerId) -> bool {
        let mut listeners = self.listeners.write();

        for all_listeners in listeners.values_mut() {
            if all_listeners.remove(&listener_id).is_some() {
                return true;
            }
        }

        false
    }

    /// Emits event in EventEmitter, passing some payload to it.
    /// All subscribed listeners will execute it's callbacks with non-mut ref
    /// to payload
    pub fn emit(&self, event: E, payload: P) {
        let callbacks = {
            let listeners = self.listeners.read();
            match listeners.get(&event) {
                Some(listeners) => listeners.values().cloned().collect::<Vec<_>>(),
                None => return,
            }
        };

        for listener in callbacks {
            (listener.callback)(&payload);
        }
    }
}
