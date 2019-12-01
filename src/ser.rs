
/// Signal to a serializable object how much of its data should be serialized
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum SerializationMode {
    /// Serialize everything sufficiently to fully reconstruct the object
    Full,
    /// Serialize the data that defines the object
    Hash,
}