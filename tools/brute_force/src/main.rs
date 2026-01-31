use std::fs::File;
use std::io::{Read, Error};

mod factory;
use factory::{init_arg_space, make_testcases};

fn main() {
    let tpl = read_tpl().expect("bad tpl");

    let args = init_arg_space();
    make_testcases(&tpl, &args, 0);
}

fn read_tpl() -> Result<String, Error> {
    let mut f = File::open("./testfiles/simple_0.tpl")?;
    let mut tpl = String::new();
    f.read_to_string(&mut tpl)?;
    Ok(tpl)
}
