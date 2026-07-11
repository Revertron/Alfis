/// Cross-event UI state, mutated on the event-bus thread and used to compose
/// status-bar text. Only ready-to-display strings cross to the UI thread.
pub struct UiStatus {
    pub mining: bool,
    pub syncing: bool,
    pub synced_blocks: u64,
    pub sync_height: u64,
    pub max_diff: u32,
    pub speed: Vec<u64>
}

impl UiStatus {
    pub fn new(threads: usize) -> Self {
        let speed = vec![0; threads];
        UiStatus { mining: false, syncing: false, synced_blocks: 0, sync_height: 0, max_diff: 0, speed }
    }

    pub fn set_thread_speed(&mut self, thread: u32, speed: u64) {
        self.speed[thread as usize] = speed;
    }

    pub fn get_speed(&self) -> u64 {
        self.speed.iter().sum()
    }
}
