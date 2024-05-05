use std::io;

use crossterm::{
    event, execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    layout::Constraint,
    prelude::*,
    symbols::border,
    widgets::{
        block::{Block, Position, Title},
        Borders, List, ListState, Paragraph,
    },
};
use x509_cert::Certificate;

use crate::info::write_cert_info;

pub type Tui = Terminal<CrosstermBackend<io::Stdout>>;

/// Sets up terminal for TUI display.
pub(crate) fn init() -> io::Result<Tui> {
    execute!(io::stdout(), EnterAlternateScreen)?;
    enable_raw_mode()?;
    Terminal::new(CrosstermBackend::new(io::stdout()))
}

/// Restores terminal to original state..
pub(crate) fn restore() -> io::Result<()> {
    execute!(io::stdout(), LeaveAlternateScreen)?;
    disable_raw_mode()?;
    Ok(())
}

#[derive(Debug)]
pub(crate) struct App {
    certs: Vec<Certificate>,
    list_state: ListState,
    exit: bool,
}

impl App {
    /// Constructs new TUI app widget.
    pub(crate) fn new(certs: &[Certificate]) -> Self {
        Self {
            exit: false,
            list_state: ListState::default().with_selected(Some(0)),
            certs: certs.to_owned(),
        }
    }

    /// Runs main execution loop for TUI app.
    pub(crate) fn run(&mut self, tui: &mut Tui) -> io::Result<()> {
        while !self.exit {
            tui.draw(|frame| self.render_frame(frame))?;
            self.handle_events()?;
        }

        Ok(())
    }

    fn render_frame(&mut self, frame: &mut Frame<'_>) {
        let title = Title::from("inspect-cert-chain".bold());
        let instructions = Title::from(Line::from(vec![" Quit ".into(), "<Q> ".blue().bold()]));

        // layout

        let outer_block = Block::default()
            .title(title.alignment(Alignment::Center))
            .title(
                instructions
                    .alignment(Alignment::Center)
                    .position(Position::Bottom),
            )
            .borders(Borders::ALL)
            .border_set(border::THICK);

        let layout = Layout::vertical([
            Constraint::Fill(1), // list
            Constraint::Fill(4), // details
        ]);

        let outer_block_area = outer_block.inner(frame.size());
        let [list_area, details_area] = layout.areas(outer_block_area);

        // content

        let list = self
            .certs
            .iter()
            .map(|cert| cert.tbs_certificate.subject.to_string())
            .collect::<List<'_>>();

        let list = list
            .highlight_style(Style::new().bold())
            .highlight_symbol("› ");

        let selected = self.list_state.selected().unwrap();

        let mut details = Vec::new();
        write_cert_info(&self.certs[selected], &mut details)
            .expect("io::Write-ing to a Vec always succeeds");

        let details = Paragraph::new(
            String::from_utf8(details)
                .expect("everything written to details buffer should be UTF-8"),
        );

        // rendering

        frame.render_widget(outer_block, frame.size());
        frame.render_stateful_widget(list, list_area, &mut self.list_state);
        frame.render_widget(details, details_area);
    }

    fn handle_events(&mut self) -> io::Result<()> {
        match event::read()? {
            // check that the event is a key press event as crossterm also emits
            // key release and repeat events on Windows
            event::Event::Key(ev) if ev.kind == event::KeyEventKind::Press => {
                self.handle_key_event(ev)
            }
            _ => {}
        };

        Ok(())
    }

    fn handle_key_event(&mut self, ev: event::KeyEvent) {
        let max = self.certs.len() - 1;
        let selected = self.list_state.selected().unwrap();

        match ev.code {
            event::KeyCode::Char('q') => self.exit = true,

            event::KeyCode::Up => self.list_state.select(Some(selected.saturating_sub(1))),

            event::KeyCode::Down => self
                .list_state
                .select(Some(selected.saturating_add(1).clamp(0, max))),

            _ => {}
        }
    }
}
