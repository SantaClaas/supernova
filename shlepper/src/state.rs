use std::{collections::HashMap, sync::Arc};

use bollard::Docker;
use tokio::sync::Mutex;

use crate::secret::Secrets;

type UpdateLocks = Arc<Mutex<HashMap<Arc<str>, Arc<Mutex<()>>>>>;

#[derive(Clone)]
pub(crate) struct State {
    docker: Docker,
    secrets: Secrets,
    pub(crate) cookie_key: cookie::Key,
    // Is there a better primitive to have one task exclusively running the update
    /// Lock to avoid multiple updates at the same time
    /// Does not lock the docker instance as other tasks are still permitted
    connection: libsql::Connection,
    update_locks: UpdateLocks,
}
