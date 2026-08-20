use std::fmt;

pub struct Config { pub name: String }

impl Config {
    pub fn new(name: &str) -> Self { Self { name: name.into() } }
}

pub trait Render { fn render(&self) -> String; }

pub enum Mode { Fast, Slow }

fn main() { let c = Config::new("a"); println!("{}", c.name); }
