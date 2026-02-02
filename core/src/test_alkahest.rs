use alkahest::{alkahest, Formula, Serialize, Deserialize};

#[alkahest(Formula, Serialize, Deserialize)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub [u8; 32]);
