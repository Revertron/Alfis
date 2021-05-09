use crate::event::Event;
use crate::simplebus::Bus;
use std::sync::Mutex;
use lazy_static::lazy_static;
use uuid::Uuid;

lazy_static! {
    static ref STATIC_BUS: Mutex<Bus<Event>> = Mutex::new(Bus::new());
}

pub fn register<F>(closure: F) -> Uuid where F: FnMut(&Uuid, Event) -> bool + Send + Sync + 'static {
    STATIC_BUS.lock().unwrap().register(Box::new(closure))
}

pub fn unregister(uuid: &Uuid) {
    STATIC_BUS.lock().unwrap().unregister(uuid);
}

pub fn post(event: Event) {
    STATIC_BUS.lock().unwrap().post(event);
}