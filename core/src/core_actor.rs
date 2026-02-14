use openmls::prelude::*;
use tokio::sync::{mpsc, oneshot};
use crate::provider::UniversalProvider;
use crate::errors::CoreError;
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

use openmls_traits::OpenMlsProvider;
use openmls_traits::crypto::OpenMlsCrypto;

use openmls::prelude::BasicCredential;
use openmls::prelude::group_info::VerifiableGroupInfo;
use openmls::prelude::ProcessedMessageContent;
use openmls_basic_credential::SignatureKeyPair;

pub enum MlsActorCommand {
    CreateGroup {
        group_id: Vec<u8>,
        respond_to: oneshot::Sender<Result<(), CoreError>>,
    },
    ProcessMessage {
        message: Vec<u8>,
        respond_to: oneshot::Sender<Result<Vec<u8>, CoreError>>,
    },
    JoinGroup {
        ratchet_tree: Vec<u8>,
        group_info: Vec<u8>,
        respond_to: oneshot::Sender<Result<(), CoreError>>,
    },
    SendApplicationMessage {
        content: Vec<u8>,
        respond_to: oneshot::Sender<Result<Vec<u8>, CoreError>>,
    },
}

pub struct MlsActor {
    provider: UniversalProvider,
    group: Option<MlsGroup>,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
}

impl MlsActor {
    pub fn new() -> Self {
        let provider = UniversalProvider::new();
        let signature_scheme = SignatureScheme::ED25519;
        let (sk, pk) = provider.crypto().signature_key_gen(signature_scheme)
            .expect("Failed to generate signature keys");

        let signer = SignatureKeyPair::from_raw(signature_scheme, sk, pk);

        let credential = CredentialWithKey {
            credential: BasicCredential::new(b"UniversalUser".to_vec()).into(),
            signature_key: signer.public().to_vec().into(),
        };

        Self {
            provider,
            group: None,
            signer,
            credential,
        }
    }

    async fn handle_create_group(&mut self, _group_id_bytes: Vec<u8>) -> Result<(), CoreError> {
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
            .wire_format_policy(WireFormatPolicy::default())
            .build();

        let group = MlsGroup::new(
            &self.provider,
            &self.signer,
            &config,
            self.credential.clone(),
        )?;

        self.group = Some(group);
        log::info!("Group created successfully");
        Ok(())
    }

    async fn handle_join_group(
        &mut self,
        ratchet_tree_bytes: Vec<u8>,
        group_info_bytes: Vec<u8>
    ) -> Result<(), CoreError> {
        // 1. Deserialize Inputs
        let ratchet_tree = RatchetTreeIn::tls_deserialize(&mut ratchet_tree_bytes.as_slice())
            .map_err(|e| CoreError::SerializationError(format!("{:?}", e)))?;

        let verifiable_group_info = VerifiableGroupInfo::tls_deserialize(&mut group_info_bytes.as_slice())
            .map_err(|e| CoreError::SerializationError(format!("{:?}", e)))?;

        // 2. Initialize the Builder
        let builder = MlsGroup::external_commit_builder()
            .with_ratchet_tree(ratchet_tree)
            .with_config(MlsGroupJoinConfig::default())
            .with_aad(vec![]);

        // 3. Create the Group State
        let initial_commit_builder = builder.build_group(
            &self.provider,
            verifiable_group_info,
            self.credential.clone()
        )?;

        // 4. Load PSKs
        let builder_with_psks = initial_commit_builder
            .load_psks(self.provider.storage())?;

        // 5. Build the Commit - OpenMLS 0.8.0 API
        let commit_builder = builder_with_psks.build(
            self.provider.rand(),   // OpenMlsRand
            self.provider.crypto(), // OpenMlsCrypto
            &self.signer,           // Signer
            |_proposal| true,       // Proposal filter (accept all)
        )?;

        // 6. Finalize the commit
        let (group, _commit_msg) = commit_builder.finalize(&self.provider)?;

        self.group = Some(group);
        log::info!("Joined group via External Commit Builder");
        Ok(())
    }

    async fn handle_process_message(&mut self, message_bytes: Vec<u8>) -> Result<Vec<u8>, CoreError> {
        if let Some(group) = &mut self.group {
            let message = MlsMessageIn::tls_deserialize(&mut message_bytes.as_slice())
                .map_err(|e| CoreError::SerializationError(format!("{:?}", e)))?;

            let protocol_msg = message.try_into_protocol_message()
                .map_err(|_| CoreError::MlsError("Received invalid message type (Welcome/GroupInfo) in protocol stream".into()))?;

            let processed_message = group.process_message(
                &self.provider,
                protocol_msg
            )?;

            match processed_message.into_content() {
                ProcessedMessageContent::ApplicationMessage(app_msg) => {
                    let bytes = app_msg.into_bytes();
                    log::info!("Received App Message: {} bytes", bytes.len());
                    Ok(bytes)
                }
                ProcessedMessageContent::ProposalMessage(proposal) => {
                    group.store_pending_proposal(self.provider.storage(), *proposal);
                    Ok(vec![])
                }
                ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                    group.merge_staged_commit(&self.provider, *staged_commit)?;
                    Ok(vec![])
                }
                _ => Ok(vec![]),
            }
        } else {
            Err(CoreError::GroupNotFound("No active group".into()))
        }
    }

    async fn handle_send_app_message(&mut self, content: Vec<u8>) -> Result<Vec<u8>, CoreError> {
        if let Some(group) = &mut self.group {
            let mls_message_out = group.create_message(
                &self.provider,
                &self.signer,
                &content
            )?;

            let bytes = mls_message_out.tls_serialize_detached()
                .map_err(|e| CoreError::SerializationError(format!("{:?}", e)))?;

            Ok(bytes)
        } else {
            Err(CoreError::GroupNotFound("No active group".into()))
        }
    }

    pub async fn run(mut self, mut receiver: mpsc::Receiver<MlsActorCommand>) {
        log::info!("MlsActor started");
        while let Some(cmd) = receiver.recv().await {
            match cmd {
                MlsActorCommand::CreateGroup { group_id, respond_to } => {
                    let res = self.handle_create_group(group_id).await;
                    let _ = respond_to.send(res);
                }
                MlsActorCommand::JoinGroup { ratchet_tree, group_info, respond_to } => {
                    let res = self.handle_join_group(ratchet_tree, group_info).await;
                    let _ = respond_to.send(res);
                }
                MlsActorCommand::ProcessMessage { message, respond_to } => {
                    let res = self.handle_process_message(message).await;
                    let _ = respond_to.send(res);
                }
                MlsActorCommand::SendApplicationMessage { content, respond_to } => {
                    let res = self.handle_send_app_message(content).await;
                    let _ = respond_to.send(res);
                }
            }
        }
        log::info!("MlsActor stopped");
    }
}