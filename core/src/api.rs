use crate::core_actor::{MlsActor, MlsActorCommand};
use crate::errors::CoreError;
use tokio::sync::{mpsc, oneshot};
use std::sync::Arc;
use tokio::runtime::Runtime;

#[derive(uniffi::Object)]
pub struct UniversalMlsCore {
    sender: mpsc::Sender<MlsActorCommand>,
    // Keeps the runtime alive
    _runtime: Arc<Runtime>,
}

#[uniffi::export]
impl UniversalMlsCore {
    #[uniffi::constructor]
    pub fn new() -> Self {
        let _ = env_logger::try_init();

        let runtime = Arc::new(Runtime::new().unwrap());
        let (sender, receiver) = mpsc::channel(100);

        let rt_clone = runtime.clone();
        rt_clone.spawn(async move {
            let actor = MlsActor::new();
            actor.run(receiver).await;
        });

        Self {
            sender,
            _runtime: runtime
        }
    }

    pub async fn create_group(&self, group_id: Vec<u8>) -> Result<(), CoreError> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(MlsActorCommand::CreateGroup { group_id, respond_to: tx })
            .await
            .map_err(|_| CoreError::Busy)?;

        rx.await.map_err(|_| CoreError::Busy)?
    }

    pub async fn join_group(&self, ratchet_tree: Vec<u8>, group_info: Vec<u8>) -> Result<(), CoreError> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(MlsActorCommand::JoinGroup {
                ratchet_tree,
                group_info,
                respond_to: tx
            })
            .await
            .map_err(|_| CoreError::Busy)?;

        rx.await.map_err(|_| CoreError::Busy)?
    }

    pub async fn process_message(&self, data: Vec<u8>) -> Result<Vec<u8>, CoreError> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(MlsActorCommand::ProcessMessage { message: data, respond_to: tx })
            .await
            .map_err(|_| CoreError::Busy)?;

        rx.await.map_err(|_| CoreError::Busy)?
    }

    pub async fn send_message(&self, content: Vec<u8>) -> Result<Vec<u8>, CoreError> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(MlsActorCommand::SendApplicationMessage { content, respond_to: tx })
            .await
            .map_err(|_| CoreError::Busy)?;

        rx.await.map_err(|_| CoreError::Busy)?
    }
}