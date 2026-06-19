fn main() -> anyhow::Result<()> {
    server::run(web::ui_router)
}
