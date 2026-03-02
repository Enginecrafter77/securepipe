pub mod crypt;

pub trait BlockFilter {
    fn transform(&mut self, buf: &mut Vec<u8>) -> anyhow::Result<()>;
}
