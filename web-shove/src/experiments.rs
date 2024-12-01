/// Restrict key id to length of <=255 as defined by the specification but do it at compile time
struct KeyId<const LENGTH: usize>([u8; LENGTH]);
impl<const LENGTH: usize> KeyId<LENGTH> {
    pub fn new(key_id: [u8; LENGTH]) -> Self {
        const {
            assert!(
                LENGTH <= u8::MAX as usize,
                "Key id length is greater than 255"
            )
        };
        Self(key_id)
    }

    #[inline]
    pub const fn length() -> usize {
        LENGTH
    }
}
fn impossible() {
    let key = KeyId::<259>::new([0; 259]);
}
