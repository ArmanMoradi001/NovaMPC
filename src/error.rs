use thiserror::Error;

#[derive(Debug, Error)]
pub enum MpcithError {
    #[error("Proof verification failed: {0}")]
    VerificationFailed(String),

    #[error("Invalid parameters: {0}")]
    InvalidParams(String),

    #[error("Circuit evaluation error: {0}")]
    CircuitError(String),

    #[error("Commitment mismatch at party {party}, repetition {repetition}")]
    CommitmentMismatch { party: usize, repetition: usize },

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Invalid witness: {0}")]
    InvalidWitness(String),

    #[error("Consistency check failed at repetition {0}")]
    ConsistencyCheckFailed(usize),
}

impl From<bincode::Error> for MpcithError {
    fn from(e: bincode::Error) -> Self {
        MpcithError::SerializationError(e.to_string())
    }
}
