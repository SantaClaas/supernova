use libsql::{Builder, Cipher, Connection, EncryptionConfig};

#[derive(thiserror::Error, Debug)]
pub(super) enum InitializeError {
    #[error("Error building database: {0}")]
    BuildError(#[source] libsql::Error),
    #[error("Error connecting to database: {0}")]
    ConnectionError(#[source] libsql::Error),
    #[error("Error executing create tables query: {0}")]
    CreateTablesError(#[source] libsql::Error),
}

pub(super) async fn initialize(
    url: String,
    token: String,
    key: Box<[u8]>,
) -> Result<Connection, InitializeError> {
    let encryption_configuration = EncryptionConfig {
        cipher: Cipher::Aes256Cbc,
        encryption_key: key.into(),
    };

    let database = Builder::new_remote_replica("database.db", url, token)
        .encryption_config(encryption_configuration)
        .build()
        .await
        .map_err(InitializeError::BuildError)?;

    let connection = database
        .connect()
        .map_err(InitializeError::ConnectionError)?;

    let create_database_batch_query = include_str!("./create_tables.sql");
    connection
        .execute_batch(&create_database_batch_query)
        .await
        .map_err(InitializeError::CreateTablesError)?;

    Ok(connection)
}
