use std::sync::LazyLock;
use std::collections::HashMap;

pub static CONDITIONS: LazyLock<HashMap<&str, [&str;4]>> = LazyLock::new(|| {
    let mut map = HashMap::new();
    map.insert("%%NUM_TASK_A%%", ["2", "4", "8", "16"]);
    map.insert("%%NUM_TASK_B%%", ["1", "1", "1", "1"]);
    map
});
