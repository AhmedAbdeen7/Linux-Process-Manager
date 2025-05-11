// app.rs
use tui::widgets::TableState;

pub struct AppState {
    pub table_state: TableState,
}

impl AppState {
    pub fn new() -> Self {
        let mut table_state = TableState::default();
        table_state.select(Some(0));
        AppState {
            table_state,
        }
    }
}

// use crate::process::SortField;

// pub struct AppState {
//     pub sort_field: SortField,
//     pub sort_descending: bool,
//     pub show_tree: bool,
// }

// impl AppState {
//     pub fn new() -> Self {
//         AppState {
//             sort_field: SortField::Cpu,
//             sort_descending: true,
//             show_tree: false,
//         }
//     }

//     pub fn set_sort_field(&mut self, field: SortField) {
//         if self.sort_field == field {
//             self.sort_descending = !self.sort_descending;
//         } else {
//             self.sort_field = field;
//             self.sort_descending = true;
//         }
//     }

//     // pub fn toggle_tree_view(&mut self) {
//     //     self.show_tree = !self.show_tree;
//     // }
// }
