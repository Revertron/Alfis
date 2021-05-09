use uuid::Uuid;
use std::collections::HashMap;

pub struct Bus<T> {
    listeners: HashMap<Uuid, Box<dyn FnMut(&Uuid, T) -> bool + Send + Sync>>
}

impl<T: Clone> Bus<T> {
    pub fn new() -> Self {
        Bus { listeners: HashMap::new() }
    }

    pub fn register<F>(&mut self, closure: F) -> Uuid where F: FnMut(&Uuid, T) -> bool + Send + Sync + 'static {
        let uuid = Uuid::new_v4();
        self.listeners.insert(uuid.clone(), Box::new(closure));
        uuid
    }

    pub fn unregister(&mut self, uuid: &Uuid) {
        self.listeners.remove(&uuid);
    }

    pub fn post(&mut self, event: T) {
        self.listeners.retain(|uuid, closure| {
            closure(uuid, event.clone())
        });
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    use crate::Bus;
    use crate::event::Event;

    #[test]
    fn test1() {
        let string = Arc::new(Mutex::new(String::from("start")));
        let bus = Arc::new(Mutex::new(Bus::new()));
        let string_copy = string.clone();
        {
            bus.lock().unwrap().register(move |_uuid, e| {
                println!("Event {:?} received!", e);
                let mut copy = string_copy.lock().unwrap();
                copy.clear();
                copy.push_str("from thread");
                false
            });
        }
        let bus2 = bus.clone();
        thread::spawn(move || {
            bus2.lock().unwrap().post(Event::BlockchainChanged { index: 1 });
        });

        let guard = string.lock().unwrap();
        thread::sleep(Duration::from_millis(100));
        println!("string = {}", &guard);
    }
}