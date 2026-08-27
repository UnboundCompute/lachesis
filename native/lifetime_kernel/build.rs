fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("locate vendored protoc");
    std::env::set_var("PROTOC", protoc);
    prost_build::compile_protos(
        &["proto/lifetime.proto", "proto/atropos.proto", "../../lachesis/core/graph.proto"],
        &["proto", "../../lachesis/core"],
    )
        .expect("compile lifetime protobuf schema");
}
