use bollard::{API_DEFAULT_VERSION, Docker};

pub(super) fn set_up() -> Result<Docker, bollard::errors::Error> {
    if cfg!(debug_assertions) {
        // I think this is docker desktop specific
        Docker::connect_with_socket(
            "/Users/claas/.docker/run/docker.sock",
            120,
            API_DEFAULT_VERSION,
        )
        // Docker::connect_with_unix("unix:///var/run/docker.sock", 120, API_DEFAULT_VERSION)
        // Docker::connect_with_unix_defaults()
    } else {
        Docker::connect_with_defaults()
    }
}
