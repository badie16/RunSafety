use std::collections::HashMap;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Clear, List, ListItem, Paragraph, Row, Table, TableState, Wrap,
};
use ratatui::Frame;

use runsafety_shared::protocol::SessionInfo;

use super::{
    dir_basename, ActivePane, App, AnalyticsTab, DetailTab, EventEntry, EventSeverity, SessionItem,
    SettingsTab, EVENT_ACTIONS,
};
use crate::cli::{format_bytes, format_timestamp};

pub fn render(f: &mut Frame, app: &mut App) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // header
            Constraint::Min(5),    // main split
            Constraint::Length(1), // footer
        ])
        .split(f.area());

    app.layout.header = outer[0];

    render_header(f, app, outer[0]);

    // Split main area: 30% sessions, 70% detail
    let panes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(outer[1]);

    app.layout.session_list = panes[0];
    app.layout.detail_pane = panes[1];

    render_session_list(f, app, panes[0]);
    render_detail_pane(f, app, panes[1]);

    render_footer(f, app, outer[2]);

    if app.show_help {
        render_help(f);
    }
    if app.show_settings {
        render_settings_overlay(f, app);
    }
}

// --- Header ---

fn render_header(f: &mut Frame, app: &mut App, area: Rect) {
    let sc = app.sessions.len();
    let ec = app.events.len();
    let uptime = super::format_duration(app.connected_at.elapsed().as_secs());

    // Track tab positions for mouse clicks
    app.layout.tab_regions.clear();
    let mut x_pos = 13u16; // " runsafety " + " "

    let tabs = [
        (DetailTab::Events, "Events"),
        (DetailTab::Resources, "Resources"),
        (DetailTab::Info, "Info"),
        (DetailTab::Analytics, "Analytics"),
    ];

    let tab_style = |tab: DetailTab, label: &str| -> Span<'static> {
        let text = format!(" {label} ");
        if app.detail_tab == tab {
            Span::styled(
                text,
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            Span::styled(text, Style::default().fg(Color::DarkGray))
        }
    };

    for (tab, label) in &tabs {
        let width = label.len() as u16 + 2; // " label "
        app.layout.tab_regions.push((x_pos, x_pos + width, *tab));
        x_pos += width;
    }

    let header = Line::from(vec![
        Span::styled(
            " runsafety ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        tab_style(DetailTab::Events, "Events"),
        tab_style(DetailTab::Resources, "Resources"),
        tab_style(DetailTab::Info, "Info"),
        tab_style(DetailTab::Analytics, "Analytics"),
        Span::raw(format!("  {sc} sessions, {ec} events | up {uptime}")),
        filter_span(app),
    ]);
    f.render_widget(Paragraph::new(header), area);
}

fn filter_span(app: &App) -> Span<'static> {
    if app.editing_filter {
        Span::styled(
            format!(" | filter: {}|", app.filter_text),
            Style::default().fg(Color::Yellow),
        )
    } else if !app.filter_text.is_empty() {
        Span::styled(
            format!(" | filter: {}", app.filter_text),
            Style::default().fg(Color::Yellow),
        )
    } else {
        Span::raw("")
    }
}

// --- Footer ---

fn render_footer(f: &mut Frame, app: &App, area: Rect) {
    let line = if let Some((msg, _)) = &app.status_msg {
        Line::from(Span::styled(
            format!(" {msg}"),
            Style::default().fg(Color::Yellow),
        ))
    } else {
        let keys =
            " j/k:Nav  Tab:Pane  Shift-Tab:View  Enter:Detail  D:Kill  S:Settings  /:Filter  ?:Help  q:Quit";
        Line::from(Span::styled(keys, Style::default().fg(Color::DarkGray)))
    };
    f.render_widget(Paragraph::new(line), area);
}

// --- Left pane: Session list ---

fn render_session_list(f: &mut Frame, app: &App, area: Rect) {
    let items = app.session_items();
    let border_color = if app.active_pane == ActivePane::Sessions {
        Color::Cyan
    } else {
        Color::DarkGray
    };

    if items.is_empty() {
        let msg = if app.sessions.is_empty() {
            " No active sessions"
        } else {
            " No sessions match filter"
        };
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" Sessions ")
            .border_style(Style::default().fg(border_color));
        f.render_widget(
            Paragraph::new(msg)
                .block(block)
                .style(Style::default().fg(Color::DarkGray)),
            area,
        );
        return;
    }

    // Map selected index back to visual row (accounting for separator)
    let active_count = app.filtered_sessions().len();
    let visual_selected = if app.selected < active_count {
        app.selected
    } else {
        // +1 for separator row
        app.selected + 1
    };

    let col_w = area.width.saturating_sub(2); // inside borders

    // Adaptive column widths based on available space
    let max_cli_len = items
        .iter()
        .filter_map(|item| match item {
            SessionItem::Active(s) | SessionItem::Ended(s) => Some(s.cli_type.len()),
            SessionItem::Separator => None,
        })
        .max()
        .unwrap_or(8) as u16;

    // Narrow pane: shrink cli and stats to give name more room
    let (cli_col_w, stats_col_w) = if col_w >= 55 {
        (max_cli_len.clamp(6, 14), 20u16)
    } else if col_w >= 40 {
        (max_cli_len.clamp(4, 10), 16u16)
    } else {
        (max_cli_len.clamp(3, 8), 12u16)
    };
    let fixed_cols = 3 + 3 + cli_col_w + stats_col_w; // dot + num + cli + stats
    let name_max = col_w.saturating_sub(fixed_cols) as usize;
    let name_max = name_max.max(4);

    let mut num = 0usize;
    let rows: Vec<Row> = items
        .iter()
        .map(|item| match item {
            SessionItem::Separator => {
                let line = format!(
                    " {:\u{2500}<width$}",
                    "\u{2500}\u{2500} Recently ended \u{2500}",
                    width = col_w.saturating_sub(2) as usize
                );
                Row::new(vec![Cell::from(Span::styled(
                    line,
                    Style::default().fg(Color::DarkGray),
                ))])
            }
            SessionItem::Active(s) => {
                num += 1;
                session_row(app, s, num, name_max, stats_col_w, false)
            }
            SessionItem::Ended(s) => {
                num += 1;
                session_row(app, s, num, name_max, stats_col_w, true)
            }
        })
        .collect();

    let widths = [
        Constraint::Length(3),           // " dot"
        Constraint::Length(3),           // number
        Constraint::Min(4),              // label (gets remaining space)
        Constraint::Length(cli_col_w),   // cli type (dynamic)
        Constraint::Length(stats_col_w), // rss + gauge + cpu
    ];

    let table = Table::new(rows, widths)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Sessions ")
                .border_style(Style::default().fg(border_color)),
        )
        .row_highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        );

    let mut state = TableState::default();
    state.select(Some(visual_selected));
    f.render_stateful_widget(table, area, &mut state);
}

fn session_row(
    app: &App,
    s: &SessionInfo,
    num: usize,
    name_max: usize,
    stats_w: u16,
    ended: bool,
) -> Row<'static> {
    let dot = if ended {
        Line::from(Span::styled(
            " \u{25cb}",
            Style::default().fg(Color::DarkGray),
        ))
    } else {
        let (ch, color) = status_dot_parts(&s.status);
        Line::from(Span::styled(format!(" {ch}"), Style::default().fg(color)))
    };

    let measuring = !ended && app.is_measuring(s.id);
    let label = truncate_str(dir_basename(&s.working_dir), name_max);
    let rss = if measuring {
        "...".to_string()
    } else {
        format_bytes(s.rss_bytes)
    };
    let cpu = if ended {
        "--".to_string()
    } else if measuring {
        "...".to_string()
    } else {
        let pct = app.cpu_percents.get(&s.pid).copied().unwrap_or(0.0);
        format!("{pct:.0}%")
    };
    let gauge: Vec<Span> = if ended {
        vec![Span::styled("[----]", Style::default().fg(Color::DarkGray))]
    } else if measuring {
        vec![Span::styled("[....]", Style::default().fg(Color::DarkGray))]
    } else {
        mini_mem_gauge(s)
    };

    let dim = if ended {
        Style::default().fg(Color::DarkGray)
    } else {
        Style::default()
    };

    // Adapt stats formatting to column width
    let stats_spans = if stats_w >= 18 {
        // Full: "  643M [████]  15%"
        let mut v = vec![Span::styled(format!("{rss:>6} "), dim)];
        v.extend(gauge);
        v.push(Span::styled(format!(" {cpu:>4}"), dim));
        v
    } else if stats_w >= 14 {
        // Compact: "643M [██] 15%"
        let mut v = vec![Span::styled(format!("{rss:>5}"), dim), Span::raw(" ")];
        v.extend(gauge);
        v.push(Span::styled(format!(" {cpu}"), dim));
        v
    } else {
        // Minimal: "643M 15%"
        vec![
            Span::styled(format!("{rss:>5}"), dim),
            Span::styled(format!(" {cpu}"), dim),
        ]
    };

    Row::new(vec![
        Cell::from(dot),
        Cell::from(Span::styled(format!("{num}"), dim)),
        Cell::from(Span::styled(label, dim)),
        Cell::from(Span::styled(s.cli_type.clone(), dim)),
        Cell::from(Line::from(stats_spans)),
    ])
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else if max <= 3 {
        s[..max].to_string()
    } else {
        format!("{}\u{2026}", &s[..max - 1])
    }
}

fn status_dot_parts(status: &str) -> (&'static str, Color) {
    if status.starts_with("Running") {
        ("\u{25cf}", Color::Green)
    } else if status.starts_with("Idle") {
        ("\u{25cf}", Color::DarkGray)
    } else if status.starts_with("HighMemory") {
        ("\u{25cf}", Color::Yellow)
    } else if status.starts_with("Leaking") {
        ("\u{25cf}", Color::Red)
    } else if status.starts_with("Restarting") {
        ("\u{25cf}", Color::Yellow)
    } else {
        ("\u{25cb}", Color::DarkGray)
    }
}

fn status_dot(status: &str) -> Line<'static> {
    let (ch, color) = status_dot_parts(status);
    Line::from(Span::styled(ch, Style::default().fg(color)))
}

// --- Right pane: detail tabs ---

fn render_detail_pane(f: &mut Frame, app: &mut App, area: Rect) {
    match app.detail_tab {
        DetailTab::Events => render_events_tab(f, app, area),
        DetailTab::Resources => render_resources_tab(f, app, area),
        DetailTab::Info => render_info_tab(f, app, area),
        DetailTab::Analytics => render_analytics_tab(f, app, area),
    }
}

// -- Events tab --

fn render_events_tab(f: &mut Frame, app: &mut App, area: Rect) {
    let session = app.selected_session();
    let title = session
        .map(|s| format!(" Events: {} ", dir_basename(&s.working_dir)))
        .unwrap_or_else(|| " Events ".into());

    let events_focused = app.active_pane == ActivePane::Events;
    let detail_focused = app.active_pane == ActivePane::EventDetail;
    let events_border = if events_focused {
        Color::Magenta
    } else {
        Color::DarkGray
    };

    let event_count = app.selected_session_events().len();

    if event_count == 0 {
        let msg = if app.sessions.is_empty() {
            " No sessions detected yet"
        } else {
            " All clear - no events for this session"
        };
        let block = Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(Style::default().fg(events_border));
        f.render_widget(
            Paragraph::new(msg)
                .block(block)
                .style(Style::default().fg(Color::DarkGray)),
            area,
        );
        return;
    }

    // Split vertically: events list on top, detail pane on bottom
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(area);

    // Store layout areas for mouse hit-testing (before borrowing app)
    app.layout.events_list_area = chunks[0];
    app.layout.event_detail_pane = chunks[1];

    let session_events = app.selected_session_events();

    // --- Top: events list ---
    let items: Vec<ListItem> = session_events
        .iter()
        .rev()
        .map(|e| {
            let sev_style = severity_style(e.severity);
            let sev_label = severity_label(e.severity);
            let ts = format_timestamp(e.timestamp);

            ListItem::new(vec![
                Line::from(vec![
                    Span::raw("  "),
                    Span::styled(format!("{ts} "), Style::default().fg(Color::DarkGray)),
                    Span::styled(format!("{sev_label:<5}"), sev_style),
                    Span::raw(" "),
                    Span::styled(
                        format!("[{}:{}]", e.cli_type, e.pid),
                        Style::default().fg(Color::Cyan),
                    ),
                ]),
                Line::from(vec![Span::raw("    "), Span::raw(e.description.clone())]),
            ])
        })
        .collect();

    let action_hint = if app.event_detail.is_some() {
        " [a]llow [b]lock [i]nvestigate [l]og [c]opy [x]close "
    } else {
        " J/K:scroll  Enter:select "
    };

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!("{title}({event_count}) "))
                .title_bottom(Line::from(action_hint).centered())
                .border_style(Style::default().fg(events_border)),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        );

    let mut state = ratatui::widgets::ListState::default();
    state.select(Some(app.event_scroll));
    f.render_stateful_widget(list, chunks[0], &mut state);

    // --- Bottom: event detail pane ---
    // Get the selected event for the detail
    let rev_idx = app.event_scroll;
    let actual_idx = session_events
        .len()
        .saturating_sub(1)
        .saturating_sub(rev_idx);
    let selected_event = session_events.get(actual_idx);

    if let Some(event) = selected_event {
        if app.event_detail.is_some() {
            let buttons = render_inline_event_detail(f, app, event, detail_focused, chunks[1]);
            app.layout.action_buttons = buttons;
        } else {
            app.layout.action_buttons.clear();
            render_event_detail_placeholder(f, detail_focused, chunks[1]);
        }
    } else {
        app.layout.action_buttons.clear();
        render_event_detail_placeholder(f, detail_focused, chunks[1]);
    }
}

fn render_event_detail_placeholder(f: &mut Frame, focused: bool, area: Rect) {
    let border_color = if focused {
        Color::Magenta
    } else {
        Color::DarkGray
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Event Detail ")
        .border_style(Style::default().fg(border_color));
    f.render_widget(
        Paragraph::new("  Select an event and press Enter to see details")
            .block(block)
            .style(Style::default().fg(Color::DarkGray)),
        area,
    );
}

/// Renders the event detail pane and returns action button hit regions.
/// Each entry: (x_start, x_end, y_row, action_index).
fn render_inline_event_detail(
    f: &mut Frame,
    app: &App,
    event: &EventEntry,
    focused: bool,
    area: Rect,
) -> Vec<(u16, u16, u16, usize)> {
    let detail = match &app.event_detail {
        Some(d) => d,
        None => return vec![],
    };

    let border_color = if focused {
        match event.severity {
            EventSeverity::Info => Color::Green,
            EventSeverity::Warning => Color::Yellow,
            EventSeverity::Critical => Color::Red,
        }
    } else {
        Color::DarkGray
    };

    // Split area: content on top, fixed button bar at bottom (3 rows)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3)])
        .split(area);
    let content_area = chunks[0];
    let button_area = chunks[1];

    // --- Content ---
    let sev_style = severity_style(event.severity);
    let sev_label = severity_label(event.severity);

    let mut lines: Vec<Line> = Vec::new();

    lines.push(Line::from(vec![
        Span::styled(
            format!(" {sev_label} "),
            sev_style.add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::styled(
            event.description.clone(),
            Style::default().add_modifier(Modifier::BOLD),
        ),
    ]));
    lines.push(Line::from(""));

    lines.push(section_title("What this means"));
    for wrapped in word_wrap(
        &detail.explanation,
        (content_area.width as usize).saturating_sub(6),
    ) {
        lines.push(Line::from(format!("  {wrapped}")));
    }

    if let Some(dns) = &detail.dns_result {
        lines.push(kv_line("  Hostname", dns));
    }

    lines.push(Line::from(""));
    lines.push(section_title("Details"));
    for (label, value) in &detail.extra_info {
        lines.push(kv_line(&format!("  {label}"), value));
    }

    if let Some(session) = app.sessions.iter().find(|s| s.pid == event.pid) {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("  Session: ", Style::default().fg(Color::DarkGray)),
            Span::raw(format!(
                "{} in {} ({})",
                session.cli_type, session.working_dir, session.status
            )),
        ]));
    }

    f.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::TOP | Borders::LEFT | Borders::RIGHT)
                    .title(" Event Detail ")
                    .border_style(Style::default().fg(border_color)),
            )
            .wrap(Wrap { trim: false }),
        content_area,
    );

    // --- Button bar (fixed position, reliable hit-testing) ---
    let btn_inner_y = button_area.y; // no top border
    let btn_inner_x = button_area.x + 1; // 1 for left border
    let mut action_spans: Vec<Span> = vec![Span::raw(" ")];
    let mut x_cursor = btn_inner_x + 1; // after " " padding
    let mut button_regions: Vec<(u16, u16, u16, usize)> = Vec::new();

    for (i, (key, label)) in EVENT_ACTIONS.iter().enumerate() {
        let is_selected = i == detail.selected_action;
        let btn_text = format!(" [{key}] {label} ");
        let btn_len = btn_text.len() as u16;
        let btn_start = x_cursor;

        if is_selected {
            action_spans.push(Span::styled(
                btn_text,
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ));
        } else {
            action_spans.push(Span::styled(
                btn_text,
                Style::default().fg(Color::White).bg(Color::DarkGray),
            ));
        }
        button_regions.push((btn_start, btn_start + btn_len, btn_inner_y, i));
        action_spans.push(Span::raw(" "));
        x_cursor += btn_len + 1;
    }

    f.render_widget(
        Paragraph::new(Line::from(action_spans)).block(
            Block::default()
                .borders(Borders::BOTTOM | Borders::LEFT | Borders::RIGHT)
                .border_style(Style::default().fg(border_color)),
        ),
        button_area,
    );

    button_regions
}

// -- Resources tab --

fn render_resources_tab(f: &mut Frame, app: &App, area: Rect) {
    let session = app.selected_session();
    let title = session
        .map(|s| format!(" Resources: {} ", dir_basename(&s.working_dir)))
        .unwrap_or_else(|| " Resources ".into());

    // Resources tab is in the detail pane, so it's "focused" when active_pane is Events
    // (detail pane shares focus concept with events for non-events tabs)
    let detail_focused = app.active_pane != ActivePane::Sessions;
    let border_color = if detail_focused {
        Color::Green
    } else {
        Color::DarkGray
    };

    if session.is_none() {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(Style::default().fg(border_color));
        f.render_widget(
            Paragraph::new(" Select a session to view resources")
                .block(block)
                .style(Style::default().fg(Color::DarkGray)),
            area,
        );
        return;
    }
    let s = session.unwrap();
    let pid = s.pid;

    let rss_data: Vec<u64> = app
        .rss_history
        .get(&pid)
        .map(|h| h.iter().copied().collect())
        .unwrap_or_default();
    let cpu_data: Vec<u64> = app
        .cpu_history
        .get(&pid)
        .map(|h| h.iter().copied().collect())
        .unwrap_or_default();

    let rss_peak = rss_data.iter().copied().max().unwrap_or(0);
    let rss_avg = if rss_data.is_empty() {
        0
    } else {
        rss_data.iter().sum::<u64>() / rss_data.len() as u64
    };
    let rss_trend = mem_trend(&rss_data);

    let cpu_now = app.cpu_percents.get(&pid).copied().unwrap_or(0.0);
    let cpu_avg = if cpu_data.is_empty() {
        0.0
    } else {
        cpu_data.iter().sum::<u64>() as f64 / cpu_data.len() as f64 / 10.0
    };
    let cpu_peak = cpu_data
        .iter()
        .copied()
        .max()
        .map(|v| v as f64 / 10.0)
        .unwrap_or(0.0);

    let chart_h = 10u16.min(area.height.saturating_sub(8));
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Length(chart_h),
            Constraint::Length(3),
            Constraint::Min(0),
        ])
        .split(area);

    let measuring = app.is_measuring(s.id);
    let rss_str = if measuring {
        "Measuring...".to_string()
    } else {
        format_bytes(s.rss_bytes)
    };
    let high_str = format_bytes(s.memory_high);
    let max_str = format_bytes(s.memory_max);
    let uptime = super::format_uptime(s.started_at);

    let rss_style = if measuring {
        Style::default().fg(Color::DarkGray)
    } else {
        Style::default().fg(Color::White)
    };

    let summary = vec![
        Line::from(vec![
            Span::styled("  Memory Used: ", Style::default().fg(Color::DarkGray)),
            Span::styled(&rss_str, rss_style),
            Span::styled("  Limit: ", Style::default().fg(Color::DarkGray)),
            Span::raw(&high_str),
            Span::styled("  Hard Limit: ", Style::default().fg(Color::DarkGray)),
            Span::raw(&max_str),
            Span::styled("  Trend: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                rss_trend.to_string(),
                Style::default().fg(trend_color(rss_trend)),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Peak: ", Style::default().fg(Color::DarkGray)),
            Span::raw(if measuring {
                "--".to_string()
            } else {
                format!("{rss_peak}M")
            }),
            Span::styled("  Avg: ", Style::default().fg(Color::DarkGray)),
            Span::raw(if measuring {
                "--".to_string()
            } else {
                format!("{rss_avg}M")
            }),
        ]),
        Line::from(vec![
            Span::styled("  CPU: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                if measuring {
                    "Measuring...".to_string()
                } else {
                    format!("{cpu_now:.1}%")
                },
                rss_style,
            ),
            Span::styled("  Peak: ", Style::default().fg(Color::DarkGray)),
            Span::raw(if measuring {
                "--".to_string()
            } else {
                format!("{cpu_peak:.1}%")
            }),
            Span::styled("  Avg: ", Style::default().fg(Color::DarkGray)),
            Span::raw(if measuring {
                "--".to_string()
            } else {
                format!("{cpu_avg:.1}%")
            }),
            Span::styled("  Uptime: ", Style::default().fg(Color::DarkGray)),
            Span::raw(&uptime),
        ]),
    ];
    f.render_widget(
        Paragraph::new(summary).block(
            Block::default()
                .borders(Borders::ALL)
                .title(title.clone())
                .border_style(Style::default().fg(border_color)),
        ),
        chunks[0],
    );

    let chart_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

    render_bar_chart(
        f,
        chart_cols[0],
        " Memory ",
        "MB",
        &rss_data,
        Color::Green,
        false,
    );
    render_bar_chart(
        f,
        chart_cols[1],
        " CPU ",
        "%",
        &cpu_data,
        Color::Yellow,
        true,
    );

    render_memory_bar(f, s, chunks[2]);
}

fn render_bar_chart(
    f: &mut Frame,
    area: Rect,
    title: &str,
    unit: &str,
    data: &[u64],
    color: Color,
    is_cpu: bool,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(Style::default().fg(color));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if data.is_empty() || inner.height == 0 || inner.width < 6 {
        f.render_widget(
            Paragraph::new("  no data").style(Style::default().fg(Color::DarkGray)),
            inner,
        );
        return;
    }

    let chart_h = inner.height as usize;
    let y_label_w = 5usize;
    let chart_w = (inner.width as usize).saturating_sub(y_label_w);
    if chart_w == 0 {
        return;
    }

    let visible: Vec<u64> = if data.len() > chart_w {
        data[data.len() - chart_w..].to_vec()
    } else {
        data.to_vec()
    };

    let max_val = if is_cpu {
        1000u64
    } else {
        visible.iter().copied().max().unwrap_or(1).max(1)
    };

    let bar_chars = [
        ' ', '\u{2581}', '\u{2582}', '\u{2583}', '\u{2584}', '\u{2585}', '\u{2586}', '\u{2587}',
        '\u{2588}',
    ];
    let mut lines: Vec<Line> = Vec::with_capacity(chart_h);

    for row in 0..chart_h {
        let row_from_bottom = chart_h - 1 - row;
        let y_label = if row == 0 {
            if is_cpu {
                format!("{:>4} ", "100%")
            } else {
                format!("{:>3}{} ", max_val, unit)
            }
        } else if row == chart_h / 2 {
            if is_cpu {
                " 50% ".to_string()
            } else {
                format!("{:>3}{} ", max_val / 2, unit)
            }
        } else if row == chart_h - 1 {
            if is_cpu {
                "  0% ".to_string()
            } else {
                format!("  0{} ", unit)
            }
        } else {
            "     ".to_string()
        };

        let mut spans = vec![Span::styled(y_label, Style::default().fg(Color::DarkGray))];

        let pad = chart_w.saturating_sub(visible.len());
        if pad > 0 {
            spans.push(Span::raw(" ".repeat(pad)));
        }

        for &val in &visible {
            let total_eighths = chart_h * 8;
            let bar_eighths = if max_val > 0 {
                ((val as f64 / max_val as f64) * total_eighths as f64) as usize
            } else {
                0
            };
            let row_start = row_from_bottom * 8;
            let row_end = row_start + 8;
            let fill = if bar_eighths >= row_end {
                8
            } else {
                bar_eighths.saturating_sub(row_start)
            };
            let ch = bar_chars[fill];
            if fill > 0 {
                spans.push(Span::styled(ch.to_string(), Style::default().fg(color)));
            } else {
                spans.push(Span::raw(" "));
            }
        }
        lines.push(Line::from(spans));
    }

    f.render_widget(Paragraph::new(lines), inner);
}

fn mem_trend(data: &[u64]) -> &'static str {
    if data.len() < 4 {
        return "--";
    }
    let half = data.len() / 2;
    let first_avg = data[..half].iter().sum::<u64>() / half as u64;
    let second_avg = data[half..].iter().sum::<u64>() / (data.len() - half) as u64;
    if second_avg > first_avg + 10 {
        "\u{2191} rising"
    } else if first_avg > second_avg + 10 {
        "\u{2193} falling"
    } else {
        "\u{2192} stable"
    }
}

fn trend_color(trend: &str) -> Color {
    if trend.contains("rising") {
        Color::Yellow
    } else if trend.contains("falling") {
        Color::Green
    } else {
        Color::DarkGray
    }
}

fn render_memory_bar(f: &mut Frame, s: &SessionInfo, area: Rect) {
    let (rss, limit) = match (s.rss_bytes, s.memory_high) {
        (Some(r), Some(l)) if l > 0 => (r, l),
        _ => {
            f.render_widget(
                Paragraph::new(" No memory limit data").block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::DarkGray)),
                ),
                area,
            );
            return;
        }
    };

    let pct = (rss as f64 / limit as f64).min(1.0);
    let inner_width = area.width.saturating_sub(4) as usize;
    let bar_width = inner_width.saturating_sub(8);
    let filled = (pct * bar_width as f64) as usize;
    let empty = bar_width.saturating_sub(filled);
    let color = pct_color(pct);

    let bar_line = Line::from(vec![
        Span::raw("  "),
        Span::styled("\u{2588}".repeat(filled), Style::default().fg(color)),
        Span::styled(
            "\u{2591}".repeat(empty),
            Style::default().fg(Color::DarkGray),
        ),
        Span::raw(format!(" {:.0}%", pct * 100.0)),
    ]);

    let rss_str = format_bytes(Some(rss));
    let limit_str = format_bytes(Some(limit));
    f.render_widget(
        Paragraph::new(bar_line).block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" Memory Used / Limit ({rss_str} / {limit_str}) "))
                .border_style(Style::default().fg(color)),
        ),
        area,
    );
}

fn mini_mem_gauge(s: &SessionInfo) -> Vec<Span<'static>> {
    let (rss, limit) = match (s.rss_bytes, s.memory_high) {
        (Some(r), Some(l)) if l > 0 => (r, l),
        _ => return vec![Span::styled("[----]", Style::default().fg(Color::DarkGray))],
    };
    let pct = (rss as f64 / limit as f64).min(1.0);
    // 4 cells wide, half-blocks for 8 steps of granularity.
    let filled_half = (pct * 8.0).round() as usize;
    let full_blocks = filled_half / 2;
    let has_half = filled_half % 2 == 1;
    let empty = 4usize
        .saturating_sub(full_blocks)
        .saturating_sub(if has_half { 1 } else { 0 });
    let color = pct_color(pct);

    let mut fill = "\u{2588}".repeat(full_blocks);
    if has_half {
        fill.push('\u{258C}');
    }
    let empty_str = " ".repeat(empty);

    vec![
        Span::styled("[", Style::default().fg(Color::DarkGray)),
        Span::styled(fill, Style::default().fg(color)),
        Span::styled(empty_str, Style::default()),
        Span::styled("]", Style::default().fg(Color::DarkGray)),
    ]
}

fn pct_color(pct: f64) -> Color {
    if pct < 0.50 {
        Color::Green
    } else if pct < 0.80 {
        Color::Yellow
    } else {
        Color::Red
    }
}

// -- Info tab --

fn render_info_tab(f: &mut Frame, app: &App, area: Rect) {
    let session = app.selected_session();
    let title = session
        .map(|s| {
            format!(
                " {} - {} (PID {}) ",
                s.cli_type,
                dir_basename(&s.working_dir),
                s.pid
            )
        })
        .unwrap_or_else(|| " Info ".into());

    let detail_focused = app.active_pane != ActivePane::Sessions;
    let border_color = if detail_focused {
        Color::Cyan
    } else {
        Color::DarkGray
    };

    if session.is_none() {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(Style::default().fg(border_color));
        f.render_widget(
            Paragraph::new(" Select a session to view details")
                .block(block)
                .style(Style::default().fg(Color::DarkGray)),
            area,
        );
        return;
    }
    let s = session.unwrap();

    let rss = format_bytes(s.rss_bytes);
    let high = format_bytes(s.memory_high);
    let max = format_bytes(s.memory_max);
    let uptime = super::format_uptime(s.started_at);
    let cpu = app
        .cpu_percents
        .get(&s.pid)
        .map(|p| format!("{p:.1}%"))
        .unwrap_or_else(|| "--".into());
    let dot = status_dot(&s.status);

    let mut lines = vec![
        Line::from(vec![
            Span::raw("  "),
            dot.spans.into_iter().next().unwrap_or_default(),
            Span::raw(format!(" {}", s.status)),
        ]),
        Line::from(""),
        section_title("Process"),
        kv_line("  CLI Type", &s.cli_type),
        kv_line("  PID", &s.pid.to_string()),
        kv_line("  Session ID", &s.id.to_string()),
        kv_line("  Working Dir", &s.working_dir),
        kv_line("  Uptime", &uptime),
        thin_separator(),
        section_title("Memory"),
        kv_line("  Memory Used", &rss),
        kv_line("  Soft Limit", &high),
        kv_line("  Hard Limit", &max),
        thin_separator(),
        section_title("CPU"),
        kv_line("  Current", &cpu),
    ];

    let session_events = app.selected_session_events();
    lines.push(thin_separator());
    lines.push(section_title("Events"));
    if session_events.is_empty() {
        lines.push(Line::from(Span::styled(
            "  No events",
            Style::default().fg(Color::DarkGray),
        )));
    } else {
        let info_c = session_events
            .iter()
            .filter(|e| e.severity == EventSeverity::Info)
            .count();
        let warn_c = session_events
            .iter()
            .filter(|e| e.severity == EventSeverity::Warning)
            .count();
        let crit_c = session_events
            .iter()
            .filter(|e| e.severity == EventSeverity::Critical)
            .count();

        lines.push(Line::from(vec![
            Span::styled("  Info: ", Style::default().fg(Color::DarkGray)),
            Span::styled(info_c.to_string(), Style::default().fg(Color::Blue)),
            Span::raw("  "),
            Span::styled("Warn: ", Style::default().fg(Color::DarkGray)),
            Span::styled(warn_c.to_string(), Style::default().fg(Color::Yellow)),
            Span::raw("  "),
            Span::styled("Crit: ", Style::default().fg(Color::DarkGray)),
            Span::styled(crit_c.to_string(), Style::default().fg(Color::Red)),
        ]));
    }

    f.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(Style::default().fg(border_color)),
        ),
        area,
    );
}

// --- Settings overlay ---

fn render_settings_overlay(f: &mut Frame, app: &App) {
    let area = centered_rect(65, 75, f.area());
    f.render_widget(Clear, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .split(area);

    let settings_tabs = [
        (SettingsTab::Governor, "Governor"),
        (SettingsTab::Networks, "Networks"),
        (SettingsTab::Plugins, "Plugins"),
        (SettingsTab::Config, "Config"),
        (SettingsTab::Alerts, "Alerts"),
    ];

    let mut tab_spans = vec![Span::raw(" ")];
    for (tab, label) in &settings_tabs {
        let text = format!(" {label} ");
        if app.settings_tab == *tab {
            tab_spans.push(Span::styled(
                text,
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ));
        } else {
            tab_spans.push(Span::styled(text, Style::default().fg(Color::DarkGray)));
        }
    }
    let hint = if app.settings_editing {
        "  editing... Enter/ Esc to finish"
    } else {
        "  j/k:Nav  Enter:Edit  Ctrl-S:Save  Tab:switch"
    };
    tab_spans.push(Span::styled(hint, Style::default().fg(Color::DarkGray)));

    f.render_widget(Paragraph::new(Line::from(tab_spans)), chunks[0]);

    match app.settings_tab {
        SettingsTab::Governor => render_settings_governor(f, app, chunks[1]),
        SettingsTab::Networks => render_settings_networks(f, app, chunks[1]),
        SettingsTab::Plugins => render_settings_plugins(f, app, chunks[1]),
        SettingsTab::Config => render_settings_config(f, app, chunks[1]),
        SettingsTab::Alerts => render_settings_alerts(f, app, chunks[1]),
    }
}

fn render_settings_governor(f: &mut Frame, app: &App, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();

    lines.push(section_title("Daemon"));
    lines.push(kv_line(
        "  Socket",
        &crate::ipc::socket_path()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "unknown".into()),
    ));
    lines.push(kv_line(
        "  Connected",
        &format!(
            "{} ago",
            super::format_duration(app.connected_at.elapsed().as_secs())
        ),
    ));
    lines.push(Line::from(""));

    lines.push(section_title("Governor Settings"));
    for (i, field) in app.settings_fields.iter().enumerate() {
        let is_selected = i == app.settings_cursor;
        let cursor_marker = if is_selected { "\u{25b6} " } else { "  " };
        let value_display = if app.settings_editing && is_selected {
            format!("{}|", app.settings_edit_buf)
        } else {
            field.value.clone()
        };
        let hint = match &field.kind {
            super::SettingsFieldKind::GovernorMode => " [\u{2190}/\u{2192} to cycle]",
            super::SettingsFieldKind::ReadOnly => "",
            super::SettingsFieldKind::Threshold if is_selected => {
                " [Enter:edit  \u{2190}/\u{2192}:\u{00b1}5%]"
            }
            super::SettingsFieldKind::MemorySize if is_selected => {
                " [Enter:edit  \u{2190}/\u{2192}:\u{00b1}0.5G]"
            }
            _ => {
                if is_selected {
                    " [Enter to edit]"
                } else {
                    ""
                }
            }
        };
        let label_style = if is_selected {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        let val_style = if app.settings_editing && is_selected {
            Style::default().fg(Color::Yellow)
        } else if is_selected {
            Style::default().fg(Color::White)
        } else {
            Style::default()
        };
        lines.push(Line::from(vec![
            Span::styled(cursor_marker.to_string(), label_style),
            Span::styled(format!("{}: ", field.label), label_style),
            Span::styled(value_display, val_style),
            Span::styled(hint.to_string(), Style::default().fg(Color::DarkGray)),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(section_title("Active Sessions"));
    if app.sessions.is_empty() {
        lines.push(Line::from("  None"));
    } else {
        let total_rss: u64 = app.sessions.iter().filter_map(|s| s.rss_bytes).sum();
        lines.push(kv_line("  Count", &app.sessions.len().to_string()));
        lines.push(kv_line("  Total RSS", &format_bytes(Some(total_rss))));
    }

    f.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Governor ")
                .border_style(Style::default().fg(Color::Cyan)),
        ),
        area,
    );
}

fn render_settings_networks(f: &mut Frame, app: &App, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();

    lines.push(section_title("Network Rules"));
    if let Some(rules) = &app.security_rules {
        if rules.network_allow.is_empty() {
            lines.push(Line::from("  No network rules configured"));
        } else {
            for entry in &rules.network_allow {
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("  {} ", entry.name),
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::raw(entry.hosts.join(", ")),
                ]));
            }
        }
        lines.push(Line::from(""));
        lines.push(section_title("File Access Rules"));
        lines.push(kv_line("  Rules loaded", &rules.file_access.len().to_string()));
        lines.push(kv_line("  Command patterns", &rules.command_pattern.len().to_string()));
    } else {
        lines.push(Line::from("  No rules loaded (using defaults)"));
    }

    f.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Networks ")
                .border_style(Style::default().fg(Color::Cyan)),
        ),
        area,
    );
}

fn render_settings_plugins(f: &mut Frame, app: &App, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();

    lines.push(section_title("Loaded Plugins"));
    if app.plugins_list.is_empty() {
        lines.push(Line::from("  No plugins loaded"));
        lines.push(Line::from("  Run 'runsafety plugin list' to manage"));
    } else {
        for plugin in &app.plugins_list {
            let status = if plugin.enabled {
                Span::styled(" [ON] ", Style::default().fg(Color::Green))
            } else {
                Span::styled(" [OFF]", Style::default().fg(Color::Red))
            };
            lines.push(Line::from(vec![
                status,
                Span::raw(" "),
                Span::styled(
                    format!("{} v{}", plugin.name, plugin.version),
                    Style::default().fg(Color::Cyan),
                ),
                Span::raw(" - "),
                Span::raw(&plugin.description),
            ]));
        }
    }

    f.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Plugins ")
                .border_style(Style::default().fg(Color::Cyan)),
        ),
        area,
    );
}

fn render_settings_config(f: &mut Frame, app: &App, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();

    lines.push(section_title("Config Management"));
    lines.push(Line::from(""));

    for (i, field) in app.settings_fields.iter().enumerate() {
        let is_selected = i == app.settings_cursor;
        let cursor_marker = if is_selected { "\u{25b6} " } else { "  " };
        let label_style = if is_selected {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        lines.push(Line::from(vec![
            Span::styled(cursor_marker.to_string(), label_style),
            Span::styled(format!("{}: ", field.label), label_style),
            Span::styled(
                field.value.clone(),
                Style::default().fg(if is_selected { Color::Yellow } else { Color::DarkGray }),
            ),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(kv_line("  Config dir", "config/"));
    lines.push(kv_line("  Export format", "TOML"));

    f.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Config ")
                .border_style(Style::default().fg(Color::Cyan)),
        ),
        area,
    );
}

fn render_settings_alerts(f: &mut Frame, app: &App, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();

    lines.push(section_title("Alert Configuration"));
    lines.push(Line::from(""));

    for (i, field) in app.settings_fields.iter().enumerate() {
        let is_selected = i == app.settings_cursor;
        let cursor_marker = if is_selected { "\u{25b6} " } else { "  " };
        let label_style = if is_selected {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        lines.push(Line::from(vec![
            Span::styled(cursor_marker.to_string(), label_style),
            Span::styled(format!("{}: ", field.label), label_style),
            Span::styled(
                field.value.clone(),
                Style::default().fg(if is_selected { Color::Yellow } else { Color::DarkGray }),
            ),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(section_title("Providers"));
    lines.push(kv_line("  Email", "SMTP"));
    lines.push(kv_line("  SMS", "Twilio"));
    lines.push(kv_line("  Webhook", "HTTP POST"));

    f.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Alerts ")
                .border_style(Style::default().fg(Color::Cyan)),
        ),
        area,
    );
}

// --- Help overlay ---

fn render_help(f: &mut Frame) {
    let area = centered_rect(55, 70, f.area());
    f.render_widget(Clear, area);

    let help_text = vec![
        Line::from(Span::styled(
            " Keyboard Shortcuts ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        help_row("j / k", "Navigate sessions"),
        help_row("BackTab", "Switch detail tab (Events/Resources/Info/Analytics)"),
        help_row("Tab", "In Analytics: cycle sub-tabs"),
        help_row("Enter", "Toggle event detail panel"),
        help_row("J / K", "Scroll events (updates detail live)"),
        help_row("PgUp/Dn", "Scroll events"),
        help_row("D", "Kill selected session"),
        help_row("/", "Filter sessions"),
        help_row("S / F3", "Settings editor (Tab to switch tabs)"),
        help_row("g / G", "Jump to first / last session"),
        help_row("q", "Quit"),
        help_row("Ctrl-C", "Force quit"),
        Line::from(""),
        Line::from(Span::styled(
            " Event Detail Actions ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        help_row("a", "Allow (add to allowlist)"),
        help_row("b", "Block (stop tool)"),
        help_row("i", "Investigate (AI analysis)"),
        help_row("l", "View audit log"),
        help_row("c", "Copy event to clipboard"),
        help_row("x / Esc", "Close detail pane"),
        Line::from(""),
        Line::from(Span::styled(
            " Mouse Support ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        help_row("Click", "Select session or event (opens detail)"),
        help_row("Click tab", "Switch to that tab"),
        help_row("Scroll", "Navigate lists"),
        help_row("Shift", "Hold for native text selection"),
        Line::from(""),
        Line::from(Span::styled(
            "  Press any key to close",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    f.render_widget(
        Paragraph::new(help_text).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Help ")
                .border_style(Style::default().fg(Color::Cyan)),
        ),
        area,
    );
}

// --- Utilities ---

fn severity_style(sev: EventSeverity) -> Style {
    match sev {
        EventSeverity::Info => Style::default().fg(Color::DarkGray),
        EventSeverity::Warning => Style::default().fg(Color::Yellow),
        EventSeverity::Critical => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
    }
}

fn severity_label(sev: EventSeverity) -> &'static str {
    match sev {
        EventSeverity::Info => "INFO",
        EventSeverity::Warning => "WARN",
        EventSeverity::Critical => "CRIT",
    }
}

fn render_analytics_tab(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .split(area);

    // Sub-tabs header
    let sub_tabs = [
        (AnalyticsTab::Summary, "Summary"),
        (AnalyticsTab::Memory, "Memory"),
        (AnalyticsTab::Security, "Security"),
    ];

    let mut tab_spans = vec![Span::raw(" ")];
    for (tab, label) in &sub_tabs {
        let text = format!(" {label} ");
        if app.analytics_tab == *tab {
            tab_spans.push(Span::styled(
                text,
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            ));
        } else {
            tab_spans.push(Span::styled(text, Style::default().fg(Color::DarkGray)));
        }
    }
    tab_spans.push(Span::raw("  Tab:switch"));
    f.render_widget(Paragraph::new(Line::from(tab_spans)), chunks[0]);

    // Content
    match app.analytics_tab {
        AnalyticsTab::Summary => render_analytics_summary(f, app, chunks[1]),
        AnalyticsTab::Memory => render_analytics_memory(f, app, chunks[1]),
        AnalyticsTab::Security => render_analytics_security(f, app, chunks[1]),
    }
}

fn render_analytics_summary(f: &mut Frame, app: &mut App, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();

    lines.push(section_title("Overview"));
    lines.push(kv_line("  Total sessions", &app.sessions.len().to_string()));
    lines.push(kv_line("  Total events", &app.events.len().to_string()));
    lines.push(kv_line("  Active sessions", &app.sessions.len().to_string()));
    lines.push(Line::from(""));

    // Events by CLI type
    let mut type_counts: HashMap<String, usize> = HashMap::new();
    for e in &app.events {
        *type_counts.entry(e.cli_type.clone()).or_insert(0) += 1;
    }
    if !type_counts.is_empty() {
        lines.push(section_title("Events by CLI"));
        let mut sorted: Vec<_> = type_counts.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        for (typ, count) in sorted.into_iter().take(10) {
            lines.push(kv_line(&format!("  {typ}"), &count.to_string()));
        }
        lines.push(Line::from(""));
    }

    // Severity breakdown
    let mut sev_info: usize = 0;
    let mut sev_warn: usize = 0;
    let mut sev_crit: usize = 0;
    for e in &app.events {
        match e.severity {
            EventSeverity::Info => sev_info += 1,
            EventSeverity::Warning => sev_warn += 1,
            EventSeverity::Critical => sev_crit += 1,
        }
    }
    if sev_info + sev_warn + sev_crit > 0 {
        lines.push(section_title("By Severity"));
        lines.push(kv_line("  Info", &sev_info.to_string()));
        lines.push(kv_line("  Warning", &sev_warn.to_string()));
        lines.push(kv_line("  Critical", &sev_crit.to_string()));
    }

    f.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Analytics: Summary ")
                .border_style(Style::default().fg(Color::Magenta)),
        ),
        area,
    );
}

fn render_analytics_memory(f: &mut Frame, app: &mut App, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();

    lines.push(section_title("Memory Stats"));

    let rss_values: Vec<u64> = app.sessions.iter().filter_map(|s| s.rss_bytes).collect();
    if rss_values.is_empty() {
        lines.push(Line::from("  No memory data available"));
    } else {
        let avg = rss_values.iter().sum::<u64>() / rss_values.len() as u64;
        let max = rss_values.iter().copied().max().unwrap_or(0);
        let min = rss_values.iter().copied().min().unwrap_or(0);
        lines.push(kv_line("  Average RSS", &format_bytes(Some(avg))));
        lines.push(kv_line("  Max RSS", &format_bytes(Some(max))));
        lines.push(kv_line("  Min RSS", &format_bytes(Some(min))));
        lines.push(kv_line("  Sessions tracked", &rss_values.len().to_string()));
    }

    lines.push(Line::from(""));
    lines.push(section_title("RSS History (last 60 samples)"));
    for session in app.sessions.iter() {
        if let Some(_history) = app.rss_history.get(&session.pid) {
            let last = _history.back().map(|v| format_bytes(Some(*v))).unwrap_or_else(|| "N/A".into());
            lines.push(kv_line(
                &format!("  PID {} ", session.pid),
                &last,
            ));
        }
    }

    f.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Analytics: Memory ")
                .border_style(Style::default().fg(Color::Magenta)),
        ),
        area,
    );
}

fn render_analytics_security(f: &mut Frame, app: &mut App, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();

    lines.push(section_title("Security Events"));

    let mut file_events = 0;
    let mut network_events = 0;
    let mut command_events = 0;
    let mut kill_events = 0;

    for e in &app.events {
        match e.severity {
            EventSeverity::Critical => kill_events += 1,
            EventSeverity::Warning => {
                // Check the raw_signal to categorize
                match &e.raw_signal {
                    super::SignalSummary::SensitiveFileAccess { .. }
                    | super::SignalSummary::BoundaryViolation { .. } => file_events += 1,
                    super::SignalSummary::UnexpectedNetwork { .. } => network_events += 1,
                    super::SignalSummary::DangerousCommand { .. }
                    | super::SignalSummary::SuspiciousChild { .. } => command_events += 1,
                    super::SignalSummary::MemoryWarning { .. }
                    | super::SignalSummary::MemoryUrgent { .. }
                    | super::SignalSummary::LeakDetected { .. } => {}
                    _ => {}
                }
            }
            _ => {}
        }
    }

    lines.push(kv_line("  File access alerts", &file_events.to_string()));
    lines.push(kv_line("  Network alerts", &network_events.to_string()));
    lines.push(kv_line("  Command alerts", &command_events.to_string()));
    lines.push(kv_line("  Critical (kills)", &kill_events.to_string()));
    lines.push(Line::from(""));

    lines.push(section_title("Recent Critical Events"));
    let criticals: Vec<_> = app.events.iter().filter(|e| e.severity == EventSeverity::Critical).collect();
    if criticals.is_empty() {
        lines.push(Line::from("  None"));
    } else {
        for e in criticals.into_iter().rev().take(5) {
            lines.push(Line::from(vec![
                Span::styled("  ! ", Style::default().fg(Color::Red)),
                Span::styled(&e.cli_type, Style::default().fg(Color::Yellow)),
                Span::raw(" "),
                Span::raw(&e.description),
            ]));
        }
    }

    f.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Analytics: Security ")
                .border_style(Style::default().fg(Color::Magenta)),
        ),
        area,
    );
}

fn section_title(title: &str) -> Line<'static> {
    Line::from(Span::styled(
        format!("  {title}"),
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    ))
}

fn thin_separator() -> Line<'static> {
    Line::from(Span::styled(
        "  \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        Style::default().fg(Color::DarkGray),
    ))
}

fn kv_line(key: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{key}: "), Style::default().fg(Color::DarkGray)),
        Span::raw(value.to_string()),
    ])
}

fn help_row(key: &str, desc: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("  {key:<10}"), Style::default().fg(Color::Yellow)),
        Span::raw(desc.to_string()),
    ])
}

fn word_wrap(text: &str, max_width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.len() + word.len() + 1 > max_width && !current.is_empty() {
            lines.push(current);
            current = String::new();
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

fn centered_rect(pct_x: u16, pct_y: u16, area: Rect) -> Rect {
    let v = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - pct_y) / 2),
            Constraint::Percentage(pct_y),
            Constraint::Percentage((100 - pct_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - pct_x) / 2),
            Constraint::Percentage(pct_x),
            Constraint::Percentage((100 - pct_x) / 2),
        ])
        .split(v[1])[1]
}
