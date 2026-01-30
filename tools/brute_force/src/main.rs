use std::fs::File;
use std::io::{Read, Write, Error};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

mod conditions;

fn main() {
    let tpl = read_tpl().expect("bad tpl");
    let _ = new_test(tpl.clone()).expect("bad test");
}

fn read_tpl() -> Result<String, Error> {
    let mut f = File::open("./testfiles/simple_0.tpl")?;
    let mut tpl = String::new();
    f.read_to_string(&mut tpl)?;
    Ok(tpl)
}

fn new_test(tpl: String) -> Result<(), Error> {
    static TEST_ID: AtomicUsize = AtomicUsize::new(1);
    let test_id = TEST_ID.fetch_add(1, Relaxed);

    let mut ret = tpl.replace("%%TEST_ID%%", format!("{}", test_id).as_str());
    for cond in crate::conditions::CONDITIONS.iter() {
        ret = ret.replace(cond.0, cond.1[0]);
    }
    write_test(test_id, &ret).expect("write test error");
    Ok(())
}

fn write_test(id: usize, test: &str) -> Result<(), Error> {
    let fname = format!("./testfiles/{}.rs", id);
    println!("test: {}", fname);
    let mut f = File::create(fname)?;
    f.write_all(test.as_bytes())?;
    Ok(())
}
