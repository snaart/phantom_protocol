use std::io::{Read, Write, Cursor};
use anyhow::Result;
use zstd::stream::read::Decoder;
use zstd::stream::write::Encoder;

// In a real build, we would include_bytes!("dictionary.bin")
// For now, we use a placeholder or empty dictionary.
const DICT_BYTES: &[u8] = &[]; 

pub struct Compression;

impl Compression {
    pub fn compress(data: &[u8]) -> Result<Vec<u8>> {
        // Level 3 is default, good balance.
        // blocks are small, so overhead of init is relevant.
        // Dictionary helps here.
        let mut encoder = Encoder::new(Vec::new(), 3)?;
        // encoder.set_dictionary(DICT_BYTES)?; // Check if this API exists in this version or use with_dictionary
        // Encoder::with_dictionary(Vec::new(), 3, DICT_BYTES) is better if available.
        
        encoder.write_all(data)?;
        let result = encoder.finish()?;
        Ok(result)
    }

    pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
        // Decoder::with_dictionary(Cursor::new(data), DICT_BYTES)
        let mut decoder = Decoder::new(Cursor::new(data))?;
        // decoder.set_dictionary(DICT_BYTES)?; 
        
        let mut buffer = Vec::new();
        decoder.read_to_end(&mut buffer)?;
        Ok(buffer)
    }
}
