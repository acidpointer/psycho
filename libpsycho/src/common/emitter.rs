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
/// Thread-safe.
/// Inner callback stored in Arc and have same lifetime as EventEmitter.
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
/// Listeners stored in concurrent hash map - DashMap, which is thread-safe.  
/// Callback and payload needs to be Send + Sync.
pub struct EventEmitter<'a, E: Send + Sync + Copy + Clone + Eq + Hash, P: Send + Sync> {
    last_id: RwLock<ListenerId>,
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

    pub fn off(&self, listener_id: ListenerId) -> bool {
        for all_listeners in self.listeners.iter() {
            match all_listeners.remove(&listener_id) {
                Some((_listener_id, _listener)) => { return true },
                None => { continue }
            }
        }

        false
    }

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
