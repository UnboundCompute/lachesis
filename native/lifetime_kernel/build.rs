fn main() {
    prost_build::compile_protos(&["proto/lifetime.proto", "proto/atropos.proto"], &["proto"])
        .expect("compile lifetime protobuf schema");
}
