use crate::crypto;
use crate::db::DbManager;
use crate::tui;
use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::widgets::ListState;
use std::io;
use zeroize::Zeroizing;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Screen {
    List,
    Add,
    Credentials,
    ConfirmDelete,
}

pub(crate) enum Note {
    Info(String),
    Error(String),
}

/// The decrypted contents of one entry, held only while it stays selected.
pub(crate) struct Revealed {
    name: String,
    pub(crate) login: Zeroizing<String>,
    pub(crate) password: Zeroizing<String>,
}

pub(crate) struct FormField {
    pub(crate) label: &'static str,
    pub(crate) value: Zeroizing<String>,
    /// Render as bullets rather than plaintext.
    pub(crate) masked: bool,
}

/// A stack of text inputs with one focused at a time. Both prompts are the
/// same widget, they just differ in how many fields they carry.
pub(crate) struct Form {
    pub(crate) fields: Vec<FormField>,
    pub(crate) focus: usize,
}

impl Form {
    fn new(fields: &[(&'static str, bool)]) -> Self {
        Self {
            fields: fields
                .iter()
                .map(|(label, masked)| FormField {
                    label,
                    value: Zeroizing::new(String::new()),
                    masked: *masked,
                })
                .collect(),
            focus: 0,
        }
    }

    fn empty() -> Self {
        Self {
            fields: Vec::new(),
            focus: 0,
        }
    }

    fn add() -> Self {
        Self::new(&[
            ("name", false),
            ("login", false),
            ("password", true),
            ("nickname", false),
            ("master password", true),
        ])
    }

    fn credentials() -> Self {
        Self::new(&[("nickname", false), ("master password", true)])
    }

    fn value(&self, index: usize) -> &str {
        self.fields[index].value.as_str()
    }

    fn advance(&mut self, delta: isize) {
        if self.fields.is_empty() {
            return;
        }

        let count = self.fields.len() as isize;
        self.focus = (self.focus as isize + delta).rem_euclid(count) as usize;
    }

    fn push(&mut self, c: char) {
        if let Some(field) = self.fields.get_mut(self.focus) {
            field.value.push(c);
        }
    }

    fn pop(&mut self) {
        if let Some(field) = self.fields.get_mut(self.focus) {
            field.value.pop();
        }
    }
}

pub struct App {
    db: DbManager,

    pub(crate) screen: Screen,
    pub(crate) note: Option<Note>,

    pub(crate) entries: Vec<String>,
    pub(crate) list_state: ListState,

    pub(crate) form: Form,
    revealed: Option<Revealed>,

    should_quit: bool,
}

impl App {
    pub fn new() -> Result<Self, redb::Error> {
        let mut app = Self {
            db: DbManager::init()?,
            screen: Screen::List,
            note: None,
            entries: Vec::new(),
            list_state: ListState::default(),
            form: Form::empty(),
            revealed: None,
            should_quit: false,
        };

        // Key names are not secret, so the vault lists without credentials.
        app.load_entries();

        Ok(app)
    }

    pub fn run(&mut self, terminal: &mut DefaultTerminal) -> io::Result<()> {
        while !self.should_quit {
            terminal.draw(|frame| tui::draw(self, frame))?;

            if let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
            {
                self.on_key(key);
            }
        }

        Ok(())
    }

    // --- rendering accessors -------------------------------------------------

    /// Only yields the secrets while their own entry is still selected, so a
    /// stale reveal can never be shown against the wrong name.
    pub(crate) fn revealed(&self) -> Option<&Revealed> {
        let revealed = self.revealed.as_ref()?;

        (self.selected_entry() == Some(revealed.name.as_str())).then_some(revealed)
    }

    pub(crate) fn selected_entry(&self) -> Option<&str> {
        let index = self.list_state.selected()?;

        self.entries.get(index).map(String::as_str)
    }

    // --- input routing -------------------------------------------------------

    fn on_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.should_quit = true;
            return;
        }

        match self.screen {
            Screen::List => self.on_list_key(key),
            Screen::Add | Screen::Credentials => self.on_form_key(key),
            Screen::ConfirmDelete => self.on_confirm_key(key),
        }
    }

    fn on_list_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            // Esc hides a revealed entry first, and only then quits.
            KeyCode::Esc => {
                if self.revealed.take().is_none() {
                    self.should_quit = true;
                }
            }
            KeyCode::Char('j') | KeyCode::Down => self.move_selection(1),
            KeyCode::Char('k') | KeyCode::Up => self.move_selection(-1),
            KeyCode::Char('a') => {
                self.form = Form::add();
                self.note = None;
                self.screen = Screen::Add;
            }
            KeyCode::Char('r') | KeyCode::Enter => {
                if self.selected_entry().is_some() {
                    self.form = Form::credentials();
                    self.note = None;
                    self.screen = Screen::Credentials;
                } else {
                    self.note = Some(Note::Error("nothing selected".into()));
                }
            }
            KeyCode::Char('d') => {
                if self.selected_entry().is_some() {
                    self.screen = Screen::ConfirmDelete;
                } else {
                    self.note = Some(Note::Error("nothing selected".into()));
                }
            }
            _ => {}
        }
    }

    fn on_form_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.form = Form::empty();
                self.screen = Screen::List;
            }
            KeyCode::Tab | KeyCode::Down => self.form.advance(1),
            KeyCode::BackTab | KeyCode::Up => self.form.advance(-1),
            KeyCode::Enter => match self.screen {
                Screen::Add => self.submit_add(),
                _ => self.submit_credentials(),
            },
            KeyCode::Backspace => self.form.pop(),
            KeyCode::Char(c) => self.form.push(c),
            _ => {}
        }
    }

    fn on_confirm_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('y') => self.delete_selected(),
            KeyCode::Char('n') | KeyCode::Esc => self.screen = Screen::List,
            _ => {}
        }
    }

    // --- actions -------------------------------------------------------------

    fn submit_add(&mut self) {
        let name = self.form.value(0).trim().to_string();
        let login = self.form.value(1).to_string();
        let password = self.form.value(2).to_string();
        let nickname = self.form.value(3).to_string();
        let master = self.form.value(4).to_string();

        if name.is_empty() {
            self.note = Some(Note::Error("an entry needs a name".into()));
            return;
        }

        if nickname.is_empty() || master.is_empty() {
            self.note = Some(Note::Error(
                "nickname and master password are both required".into(),
            ));
            return;
        }

        // `encrypt` hands back the identity's public key, so the second blob
        // can be sealed with it directly — one Argon2 hash covers both.
        let (sealed_login, public_key) = match crypto::encrypt(&nickname, &master, login.as_bytes())
        {
            Ok(sealed) => sealed,
            Err(error) => {
                self.note = Some(Note::Error(format!("could not encrypt: {error}")));
                return;
            }
        };

        let sealed_password = match crypto::seal(&public_key, password.as_bytes()) {
            Ok(sealed) => sealed,
            Err(error) => {
                self.note = Some(Note::Error(format!("could not encrypt: {error}")));
                return;
            }
        };

        if let Err(error) = self.db.store(&name, &sealed_login, &sealed_password) {
            self.note = Some(Note::Error(format!("could not write vault: {error}")));
            return;
        }

        self.form = Form::empty();
        self.revealed = None;
        self.screen = Screen::List;
        self.load_entries();

        if let Some(index) = self.entries.iter().position(|entry| *entry == name) {
            self.list_state.select(Some(index));
        }

        self.note = Some(Note::Info(format!("saved {name}")));
    }

    fn submit_credentials(&mut self) {
        let nickname = self.form.value(0).to_string();
        let master = self.form.value(1).to_string();

        let Some(name) = self.selected_entry().map(str::to_string) else {
            self.screen = Screen::List;
            return;
        };

        let (sealed_login, sealed_password) = match self.db.retrieve_credentials(&name) {
            Ok(Some(credentials)) => credentials,
            Ok(None) => {
                self.note = Some(Note::Error(format!("{name} is no longer in the vault")));
                self.screen = Screen::List;
                return;
            }
            Err(error) => {
                self.note = Some(Note::Error(format!("could not read vault: {error}")));
                self.screen = Screen::List;
                return;
            }
        };

        let Some(login) = self.open_field(&nickname, &master, &sealed_login) else {
            return;
        };
        let Some(password) = self.open_field(&nickname, &master, &sealed_password) else {
            return;
        };

        self.revealed = Some(Revealed {
            name,
            login,
            password,
        });

        self.form = Form::empty();
        self.screen = Screen::List;
        self.note = None;
    }

    fn open_field(
        &mut self,
        nickname: &str,
        master: &str,
        sealed: &[u8],
    ) -> Option<Zeroizing<String>> {
        match crypto::decrypt(nickname, master, sealed) {
            Ok(plain) => match String::from_utf8(plain) {
                Ok(text) => Some(Zeroizing::new(text)),
                Err(_) => {
                    self.note = Some(Note::Error("entry is not valid UTF-8".into()));
                    None
                }
            },
            Err(_) => {
                self.form = Form::credentials();
                self.note = Some(Note::Error("wrong nickname or master password".into()));
                None
            }
        }
    }

    fn delete_selected(&mut self) {
        let Some(name) = self.selected_entry().map(str::to_string) else {
            self.screen = Screen::List;
            return;
        };

        self.note = match self.db.delete(&name) {
            Ok(true) => Some(Note::Info(format!("deleted {name}"))),
            Ok(false) => Some(Note::Error(format!("{name} was already gone"))),
            Err(error) => Some(Note::Error(format!("could not write vault: {error}"))),
        };

        self.revealed = None;
        self.screen = Screen::List;
        self.load_entries();
    }

    fn load_entries(&mut self) {
        let keys = match self.db.retrieve_keys() {
            Ok(keys) => keys,
            // A vault that has never been written has no table yet.
            Err(redb::Error::TableDoesNotExist(_)) => Vec::new(),
            Err(error) => {
                self.note = Some(Note::Error(format!("could not read vault: {error}")));
                return;
            }
        };

        self.entries = keys;

        if self.entries.is_empty() {
            self.list_state.select(None);
        } else {
            let index = self
                .list_state
                .selected()
                .unwrap_or(0)
                .min(self.entries.len() - 1);

            self.list_state.select(Some(index));
        }
    }

    fn move_selection(&mut self, delta: isize) {
        if self.entries.is_empty() {
            return;
        }

        let last = self.entries.len() - 1;
        let current = self.list_state.selected().unwrap_or(0) as isize;
        let next = (current + delta).clamp(0, last as isize) as usize;

        if Some(next) != self.list_state.selected() {
            // Drop the plaintext as soon as its entry stops being selected.
            self.revealed = None;
        }

        self.list_state.select(Some(next));
    }
}
