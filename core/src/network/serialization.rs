use rkyv::{Archive, Serialize, Deserialize};
use rkyv::ser::{serializers::AllocSerializer, Serializer};
use rkyv::validation::validators::DefaultValidator;
use bytecheck::CheckBytes;
use anyhow::{Result, anyhow};

pub trait Serializable: Archive + for<'a> Serialize<AllocSerializer<256>> {}
impl<T: Archive + for<'a> Serialize<AllocSerializer<256>>> Serializable for T {}

pub fn serialize<T>(value: &T) -> Result<Vec<u8>>
where
    T: Serializable,
{
    let mut serializer = AllocSerializer::<256>::default();
    serializer.serialize_value(value)
        .map_err(|e| anyhow!("Serialization error: {}", e))?;
    let bytes = serializer.into_serializer().into_inner();
    Ok(bytes.to_vec())
}

pub fn deserialize<'a, T>(bytes: &'a [u8]) -> Result<T>
where
    T: rkyv::Archive,
    T::Archived: Deserialize<T, rkyv::Infallible> + CheckBytes<DefaultValidator<'a>> + 'a,
{
    // SAFE: We use check_archived_root which validates the byte structure
    let archived = rkyv::check_archived_root::<T>(bytes)
        .map_err(|e| anyhow!("Deserialization validation error: {}", e))?;
        
    let deserialized: T = archived.deserialize(&mut rkyv::Infallible)
        .map_err(|e| anyhow!("Deserialization error: {}", e))?;
        
    Ok(deserialized)
}
