use crate::KEY_ID_LENGTH;

const SALT_LENGTH: usize = 16;

struct Header<const KEY_ID_SIZE: u8> {
    salt: [u8; SALT_LENGTH],
    record_size: u32,
    key_id: [u8; KEY_ID_LENGTH as usize],
}

struct Content {}

#[cfg(test)]
mod test {
    #[test]
    fn can_run_rfc_8188_example() {
        // Arrange
    }
}
