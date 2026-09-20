use password_manager::App;

fn main() {
    let mut app = match App::new() {
        Ok(app) => app,
        Err(error) => {
            eprintln!("could not open the vault: {error}");
            std::process::exit(1);
        }
    };

    if let Err(error) = ratatui::run(|terminal| app.run(terminal)) {
        eprintln!("terminal error: {error}");
        std::process::exit(1);
    }
}
