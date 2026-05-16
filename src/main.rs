#[tokio::main]
async fn main() -> anyhow::Result<()> {
    parallax::cli::run().await
}
