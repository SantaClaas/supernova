use std::path::{Path, PathBuf};

use tower_http::services::ServeDir;

fn get_public_path() -> PathBuf {
    if cfg!(debug_assertions) {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("public")
    } else {
        let mut path = std::env::current_exe().unwrap_or_else(|error| {
                tracing::warn!(
                    "Could not get current executable path. Will serve static files from relative \"public\" directory. Causing Error: {}",
                    error
                );
                "public".into()
            });

        // We want the directory containing the executable not the executable itself
        _ = path.pop();

        path.join("public")
    }
}

pub(super) fn serve() -> ServeDir {
    let public_path = get_public_path();
    tracing::debug!("Serving files from: {}", public_path.display());
    ServeDir::new(public_path)
        .precompressed_br()
        .precompressed_deflate()
        .precompressed_gzip()
        .precompressed_zstd()
}
