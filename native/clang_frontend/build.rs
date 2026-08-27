fn main() {
    println!("cargo:rerun-if-changed=../../lachesis/core/graph.proto");
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("locate vendored protoc");
    std::env::set_var("PROTOC", protoc);
    prost_build::compile_protos(
        &["../../lachesis/core/graph.proto"],
        &["../../lachesis/core"],
    )
    .expect("compile graph protobuf schema");
}
