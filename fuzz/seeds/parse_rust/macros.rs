macro_rules! twice { ($e:expr) => { $e; $e }; }
#[cfg(test)]
mod tests {
    #[test]
    fn t() { twice!(assert!(true)); }
}
