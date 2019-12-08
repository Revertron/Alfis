#![windows_subsystem = "windows"]
extern crate pancurses;
use pancurses::{initscr, endwin, Input, noecho, resize_term, Window, start_color, init_pair, colorpair::ColorPair, COLOR_PAIR};

use wyrd_ns::{Blockchain, Block, Action, Transaction, Signature, Key};

const COLOR_TEXT: i16 = 0;
const COLOR_TITLE: i16 = 1;
const COLOR_MENU_NORMAL: i16 = 2;
const COLOR_MENU_FOCUSED: i16 = 3;
const COLOR_STATUS: i16 = 4;

fn main() {
    println!("Wyrd DNS 0.1.0");
    run_interface();
    //test_blockchain()
}

fn init_colors() {
    start_color();
    let background = pancurses::COLOR_BLACK;
    let accent = pancurses::COLOR_CYAN;
    let text = pancurses::COLOR_WHITE;

    init_pair(COLOR_TEXT, text, background);
    init_pair(COLOR_TITLE, background, accent);
    init_pair(COLOR_MENU_NORMAL, text, background);
    init_pair(COLOR_MENU_FOCUSED, background, accent);
    init_pair(COLOR_STATUS, background, accent);
}

fn draw_title(win: &Window, title: &str) {
    win.color_set(COLOR_TITLE);
    win.mvprintw(0, win.get_beg_x(), format!("{:width$}", title, width = win.get_max_x() as usize));
}

fn draw_status(win: &Window, title: &str) {
    win.color_set(COLOR_TITLE);
    win.mvprintw(win.get_max_y() - 1, win.get_beg_x(), format!("{:width$}", title, width = win.get_max_x() as usize));
}

#[derive(Debug)]
pub struct MenuItem {
    id: usize,
    caption: String,
    hint: String
}

impl MenuItem {
    pub fn simple<S: Into<String>>(id: usize, caption: S) -> Self {
        MenuItem{ id, caption: caption.into(), hint: String::new() }
    }

    pub fn full<S: Into<String>>(id: usize, caption: S, hint: S) -> Self {
        MenuItem{ id, caption: caption.into(), hint: hint.into() }
    }

    pub fn separator() -> Self {
        MenuItem { id: 0, caption: String::new(), hint: String::new() }
    }

    pub fn is_separator(&self) -> bool {
        self.caption.is_empty()
    }

    pub fn get_id(&self) -> usize {
        self.id
    }

    pub fn get_caption(&self) -> &str {
        &self.caption
    }

    pub fn get_hint(&self) -> &str {
        &self.hint
    }
}

struct Menu {
    x: i32,
    y: i32,
    items: Vec<MenuItem>,
    position: usize,
    max_width: usize,
}

impl Menu {
    fn new(x: i32, y: i32, items: Vec<MenuItem>) -> Self {
        let mut max = 0;
        for item in items.iter() {
            if item.get_caption().len() > max {
                max = item.get_caption().len();
            }
        }
        Menu{ x, y, items, position: 0, max_width: max }
    }

    fn up(&mut self) {
        if self.position > 0 {
            self.position = self.position - 1;
            if self.items[self.position].is_separator() {
                self.up();
            }
        }
    }

    fn down(&mut self) {
        if self.position < (self.items.len() - 1) {
            self.position = self.position + 1;
            if self.items[self.position].is_separator() {
                self.down();
            }
        }
    }

    fn position(&self) -> usize {
        self.position
    }

    fn current(&self) -> &MenuItem {
        &self.items[self.position]
    }

    fn paint(&self, win: &Window) {
        let mut pos = 0;
        for item in self.items.iter() {
            let color = { if pos == self.position {COLOR_MENU_FOCUSED} else {COLOR_MENU_NORMAL} };
            win.color_set(color);
            win.mvprintw(self.y + pos as i32, self.x, format!(" {:width$} ", item.get_caption(), width = self.max_width));
            pos = pos + 1;
        }
    }
}

fn run_interface() {
    let window = initscr();
    resize_term(24, 80);
    init_colors();
    draw_title(&window, " Wyrd 0.1.0");
    window.refresh();
    window.keypad(true);
    window.timeout(20);
    pancurses::noecho();
    window.keypad(true);
    pancurses::curs_set(0);
    let mut menu = create_menu();

    loop {
        match window.getch() {
            Some(Input::Character(c)) => {
                if c == '\n' {
                    println!("Selected {:?}", menu.current());
                } else {
                    window.addch(c);
                }
            },
            Some(Input::KeyResize) => { resize_term(0, 0); },
            Some(Input::KeyUp) => { menu.up(); },
            Some(Input::KeyDown) => { menu.down(); },
            Some(Input::KeyEnter) => { println!("Selected {:?}", menu.current()); },
            Some(Input::KeyDC) => break,
            Some(input) => { window.addstr(&format!("{:?}", input)); },
            None => ()
        }
        draw_status(&window, menu.current().get_hint());
        menu.paint(&window);
        window.refresh();
    }
    endwin();
}

fn create_menu() -> Menu {
    let menu_items = vec![
        MenuItem::full(1, "Key create", "Create keypair to sign domain operations"),
        MenuItem::full(2, "Key load", "Load existing keypair"),
        MenuItem::separator(),
        MenuItem::full(3, "Domain create new", "Create and mine new domain"),
        MenuItem::full(4, "Domain change records", "Change DNS records for your domain"),
        MenuItem::full(5, "Domain renew", "Renew your domain name, needs additional mining"),
        MenuItem::full(6, "Domain transfer", "Transfer your domain to a new owner (new keypair)"),
        MenuItem::separator(),
        MenuItem::full(7, "Test blockchain", "Do some test blockchain operations with simple mining")
    ];
    Menu::new(1, 3, menu_items)
}

fn test_blockchain() -> () {
    let mut blockchain = Blockchain::new(42, 0);
    println!("Blockchain with genesis block has been created");
    let signature = Signature::from_file("default.key", "").unwrap();

    // Creating transaction
    let action = Action::new_domain("test.zz".to_owned(), &signature, vec!["AAAA IN 301:2925::1".to_owned()], vec!["testing".to_owned(), "example".to_owned()], 365);
    let mut transaction = Transaction::new(action, signature.get_public().clone());

    // Signing it with private key from Signature
    let sign_hash = signature.sign(&transaction.get_bytes());
    transaction.set_signature(Key::from_bytes(&sign_hash));

    // Creating a block with that signed transaction
    let mut block = blockchain.new_block(transaction);

    // Mining the nonce
    block.mine();

    // Our block is ready, we can print it and add to Blockchain
    let s = serde_json::to_string(&block).unwrap();
    println!("Serialized block:\n{}", s);
    blockchain.add_block(block);
    println!("Second block added");

    let block2: Block = serde_json::from_str(&s).unwrap();
    println!("DeSerialized block:\n{:?}", block2);

    // Let's check if the blockchain is valid
    if blockchain.check() {
        println!("Blockchain is correct");
    } else {
        println!("Blockchain is corrupted, aborting");
    }
}
