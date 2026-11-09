/// A scope set whose check always passes, which the sealed trait refuses.
struct Everything;

impl piquel_auth::ScopeSet for Everything {}

fn main() {}
