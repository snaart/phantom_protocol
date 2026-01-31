use rkyv::{Archive, Deserialize, Serialize};

#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
#[archive(check_bytes)] // Critical for security (RCE prevention)
pub enum ControlMessage {
    /// Register a KeyPackage for a user identity.
    /// Identity is typically hash of public key or some unique ID.
    Register {
        identity: Vec<u8>,
        key_package: Vec<u8>, // Serialized KeyPackage
        // Security Fix: Identity Proof
        signature: Vec<u8>,   // Signature over (identity + key_package)
        verifying_key: Vec<u8>, // Public Key to verify signature
    },
    /// Fetch a KeyPackage for a target user to send them a Welcome message.
    FetchKeyPackage {
        identity: Vec<u8>,
    },
    /// Response containing the KeyPackage (or None if not found)
    KeyPackageResponse {
        key_package: Option<Vec<u8>>,
    },
    /// Upload a Welcome message for a specific user.
    DeliverWelcome {
        recipient_identity: Vec<u8>,
        welcome_message: Vec<u8>,
    },
    /// Fetch pending Welcome messages for the requesting user.
    FetchWelcome {
        identity: Vec<u8>,
    },
    /// Response containing a list of Welcome messages.
    WelcomeResponse {
        welcomes: Vec<Vec<u8>>,
    },
    /// Error response
    Error(String),
}
