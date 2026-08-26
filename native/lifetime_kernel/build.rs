fn main() {
    prost_build::compile_protos(
        &["proto/lifetime.proto", "proto/atropos.proto", "../../lachesis/core/graph.proto"],
        &["proto", "../../lachesis/core"],
    )
        .expect("compile lifetime protobuf schema");
}
