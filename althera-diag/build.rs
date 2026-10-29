use embed_manifest::manifest::{ActiveCodePage, DpiAwareness};
use embed_manifest::{embed_manifest, new_manifest};

fn main() {
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        // asInvoker: nunca pede elevação sozinho; Common Controls v6 p/ visual moderno.
        // Code page do sistema (não UTF-8): a saída de ipconfig/ping vem na OEM do Windows.
        embed_manifest(
            new_manifest("Althera.Diag")
                .dpi_awareness(DpiAwareness::PerMonitorV2)
                .active_code_page(ActiveCodePage::System),
        )
        .expect("falha ao embutir manifest");
        // ícone (id 1) + cabeçalho (BANNER) da marca Althera
        embed_resource::compile("assets/app.rc", embed_resource::NONE)
            .manifest_required()
            .expect("falha ao compilar recursos");
    }
    println!("cargo:rerun-if-changed=assets");
    println!("cargo:rerun-if-changed=build.rs");
}
