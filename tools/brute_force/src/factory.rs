use std::fs::File;
use std::io::{Write, Error};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

type Arg<'a> = (&'a str, Vec<&'a str>);
type ArgVec<'a> = Vec<Arg<'a>>;

pub fn init_arg_space() -> ArgVec<'static> {
    vec![
        ("%%NUM_TASK_A%%", vec!["2", "4", "8", "16"]),
        ("%%NUM_TASK_B%%", vec!["1"]),
    ]
}

pub fn make_testcases(tpl: &String, args: &ArgVec, level: usize) {
    if level >= args.len() {
        let fid = new_id();
        let ret = tpl.replace("%%TEST_ID%%", &fid);
        write_to_file(&fid, &ret).expect("write test error");
        return;
    }

    for val in args[level].1.iter() {
        let ret = tpl.replace(args[level].0, val);
        make_testcases(&ret, &args, level + 1);
    }
}

fn new_id() -> String {
    static TEST_ID: AtomicUsize = AtomicUsize::new(1);
    format!("{}", TEST_ID.fetch_add(1, Relaxed))
}

fn write_to_file(fid: &str, test: &str) -> Result<(), Error> {
    let fname = format!("./testfiles/{}.rs", fid);
    let mut f = File::create(fname)?;
    f.write_all(test.as_bytes())?;
    Ok(())
}
