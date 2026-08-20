pub unsafe fn raw<T: Clone + Send>(p: *mut T, n: usize) -> Vec<T> {
    std::slice::from_raw_parts(p, n).to_vec()
}
pub async fn go<'a, F>(f: F) where F: Fn(&'a str) -> Result<(), Box<dyn std::error::Error>> {}
