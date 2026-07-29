use std::{collections::HashMap, time::Duration};

use bollard::query_parameters::ListContainersOptions;

use crate::state::State;

mod label {
    /// Tag to mark containers managed by tugboat
    pub(super) const TAG: &str = "moe.cla.tugboat.tugged";
}

/// Runs forever and cleans up expired app data
pub(crate) async fn start(state: State) {
    // It is not important that it cleans exactly, but it is important that it happens regularly
    // Duration from minutes is experimental currently
    let mut interval = tokio::time::interval(Duration::from_secs(24 * 60 * 60));
    let filters = Some(HashMap::from([(
        "label".to_owned(),
        vec![label::TAG.to_owned()],
    )]));
    loop {
        interval.tick().await;
        // Clean up dead containers
        let result = state
            .docker
            .list_containers(Some(ListContainersOptions {
                all: true,
                filters: filters.clone(),
                ..Default::default()
            }))
            .await;

        let container_ids: Vec<String> = match result {
            Ok(containers) => containers
                .into_iter()
                .filter_map(|container| container.id)
                .collect(),
            Err(error) => {
                tracing::error!("Error listing containers for database cleanup: {:?}", error);
                continue;
            }
        };

        if container_ids.is_empty() {
            continue;
        }

        if container_ids.len() >= i16::MAX as usize {
            tracing::error!(
                "Expected containers to not exceed parameter limit, got {}",
                container_ids.len()
            );
            continue;
        }

        let query = format!(
            "DELETE FROM tokens WHERE container_id NOT IN ({})",
            (1..=container_ids.len())
                .map(|index| format!("?{index}"))
                .collect::<Vec<_>>()
                .join(", ")
        );

        match state.connection.execute(&query, container_ids).await {
            Ok(deleted_rows) => {
                tracing::info!(
                    "Cleaned up {deleted_rows} containers from database that no longer exist"
                )
            }
            Err(error) => {
                tracing::error!("Error cleaning up containers from database: {:?}", error)
            }
        };
    }
}
