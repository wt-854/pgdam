fn main() -> Result<(), Box<dyn std::error::Error>> {
    prost_build::compile_protos(&["../contracts/audit_event.proto"], &["../contracts/"])?;
    Ok(())
}
