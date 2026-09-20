use crate::app::{App, Form, Note, Screen};
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Clear, List, ListItem, Paragraph, Wrap};

const ACCENT: Color = Color::Cyan;
const DIM: Color = Color::DarkGray;

pub(crate) fn draw(app: &mut App, frame: &mut Frame) {
    let [body, footer] =
        Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).areas(frame.area());

    draw_vault(app, frame, body);
    draw_footer(app, frame, footer);

    match app.screen {
        Screen::Add => draw_form(
            &app.form,
            " new entry ",
            "each entry is sealed under the credentials you type here",
            frame,
            body,
        ),
        Screen::Credentials => draw_form(
            &app.form,
            &format!(" unlock {} ", app.selected_entry().unwrap_or("entry")),
            "tab next field · enter reveal · esc cancel",
            frame,
            body,
        ),
        Screen::ConfirmDelete => draw_confirm(app, frame, body),
        Screen::List => {}
    }
}

// --- vault ------------------------------------------------------------------

fn draw_vault(app: &mut App, frame: &mut Frame, area: Rect) {
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).areas(area);

    let title = format!(" entries ({}) ", app.entries.len());

    if app.entries.is_empty() {
        let block = panel_block(&title);
        let inner = block.inner(left);
        frame.render_widget(block, left);
        frame.render_widget(
            Paragraph::new("vault is empty\n\npress a to add one")
                .style(Style::default().fg(DIM))
                .alignment(Alignment::Center),
            inner,
        );
    } else {
        let items: Vec<ListItem> = app
            .entries
            .iter()
            .map(|entry| ListItem::new(Line::from(entry.as_str())))
            .collect();

        let list = List::new(items)
            .block(panel_block(&title))
            .highlight_symbol("▌ ")
            .highlight_style(
                Style::default()
                    .fg(ACCENT)
                    .add_modifier(Modifier::BOLD | Modifier::REVERSED),
            );

        frame.render_stateful_widget(list, left, &mut app.list_state);
    }

    draw_details(app, frame, right);
}

fn draw_details(app: &App, frame: &mut Frame, area: Rect) {
    let Some(name) = app.selected_entry() else {
        let block = panel_block(" credentials ");
        let inner = block.inner(area);
        frame.render_widget(block, area);
        frame.render_widget(
            Paragraph::new("no entry selected")
                .style(Style::default().fg(DIM))
                .alignment(Alignment::Center),
            inner,
        );

        return;
    };

    let block = panel_block(&format!(" {name} "));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let lines = match app.revealed() {
        Some(revealed) => vec![
            Line::from(""),
            credential("login", &revealed.login, Color::White),
            Line::from(""),
            credential("password", &revealed.password, Color::Green),
            Line::from(""),
            Line::from(Span::styled("esc to hide", Style::default().fg(DIM))),
        ],
        None => vec![
            Line::from(""),
            credential("login", "••••••••", DIM),
            Line::from(""),
            credential("password", "••••••••", DIM),
            Line::from(""),
            Line::from(Span::styled(
                "locked — press enter to decrypt",
                Style::default().fg(Color::Yellow),
            )),
        ],
    };

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner);
}

fn credential(label: &str, value: &str, color: Color) -> Line<'static> {
    let shown = if value.is_empty() { "(empty)" } else { value };

    Line::from(vec![
        Span::styled(format!(" {label:<10}"), Style::default().fg(DIM)),
        Span::styled(
            shown.to_string(),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ),
    ])
}

// --- modals -----------------------------------------------------------------

fn draw_form(form: &Form, title: &str, hint: &str, frame: &mut Frame, area: Rect) {
    let rows = form.fields.len() as u16;
    let panel = centered(area, 60, rows * 3 + 4);
    frame.render_widget(Clear, panel);

    let block = panel_block(title);
    let inner = block.inner(panel);
    frame.render_widget(block, panel);

    let mut constraints: Vec<Constraint> = vec![Constraint::Length(3); form.fields.len()];
    constraints.push(Constraint::Min(0));

    let chunks = Layout::vertical(constraints).split(inner);

    for (index, field) in form.fields.iter().enumerate() {
        let shown = if field.masked {
            "•".repeat(field.value.chars().count())
        } else {
            field.value.to_string()
        };

        frame.render_widget(
            input(field.label, shown.as_str(), form.focus == index),
            chunks[index],
        );
    }

    frame.render_widget(
        Paragraph::new(hint.to_string())
            .style(Style::default().fg(DIM))
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true }),
        chunks[form.fields.len()],
    );
}

fn draw_confirm(app: &App, frame: &mut Frame, area: Rect) {
    let panel = centered(area, 52, 7);
    frame.render_widget(Clear, panel);

    let block = panel_block(" delete entry ").border_style(Style::default().fg(Color::Red));
    let inner = block.inner(panel);
    frame.render_widget(block, panel);

    let name = app.selected_entry().unwrap_or("this entry");
    let lines = vec![
        Line::from(""),
        Line::from(format!("permanently delete {name}?")),
        Line::from(""),
        Line::from(Span::styled(
            "y delete · n cancel",
            Style::default().fg(DIM),
        )),
    ];

    frame.render_widget(Paragraph::new(lines).alignment(Alignment::Center), inner);
}

// --- chrome -----------------------------------------------------------------

fn draw_footer(app: &App, frame: &mut Frame, area: Rect) {
    if let Some(note) = &app.note {
        let (text, color) = match note {
            Note::Info(text) => (text.as_str(), Color::Green),
            Note::Error(text) => (text.as_str(), Color::Red),
        };

        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                format!(" {text}"),
                Style::default().fg(color),
            ))),
            area,
        );

        return;
    }

    let keys: &[(&str, &str)] = match app.screen {
        Screen::List => &[
            ("a", "add"),
            ("enter", "reveal"),
            ("d", "delete"),
            ("j/k", "move"),
            ("q", "quit"),
        ],
        Screen::Add | Screen::Credentials => &[
            ("tab", "next field"),
            ("enter", "submit"),
            ("esc", "cancel"),
        ],
        Screen::ConfirmDelete => &[("y", "delete"), ("n", "cancel")],
    };

    let mut spans = vec![Span::raw(" ")];
    for (key, label) in keys {
        spans.push(Span::styled(
            *key,
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(
            format!(" {label}  "),
            Style::default().fg(DIM),
        ));
    }

    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn panel_block(title: &str) -> Block<'static> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .title(Span::styled(
            title.to_string(),
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ))
}

fn input(label: &str, value: &str, focused: bool) -> Paragraph<'static> {
    let border = if focused { ACCENT } else { DIM };
    let caret = if focused { "▏" } else { "" };

    Paragraph::new(Line::from(format!("{value}{caret}"))).block(
        Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(border))
            .title(Span::styled(label.to_string(), Style::default().fg(border))),
    )
}

/// A `width` × `height` rectangle centred inside `area`, clamped to fit.
fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);

    Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    }
}
