use super::*;
use std::panic;
use std::sync::atomic::{AtomicIsize, Ordering};
use util::mem_util::*;

const GREEN_OK: &str = "\x1b[0;32mok\x1b[0m";
const RED_FAILED: &str = "\x1b[0;31mFAILED\x1b[0m";

pub fn run_unit_tests(name_prefix: *const c_char) -> Result<isize> {
    if name_prefix.is_null() {
        let tests = inventory::iter::<TestCase>.into_iter().collect::<Vec<_>>();

        run_tests(&tests)
    } else {
        let func_name_prefix = unsafe {
            from_user::clone_cstring_safely(name_prefix)?
                .to_string_lossy()
                .into_owned()
        };

        let tests = inventory::iter::<TestCase>
            .into_iter()
            .filter(|case| case.name().starts_with(&func_name_prefix))
            .collect::<Vec<_>>();

        let test_count = tests.len();
        if test_count == 0 {
            warn!("No test is run.");
            return Ok(0);
        }

        run_tests(&tests)
    }
}

fn run_tests(tests: &[&TestCase]) -> Result<isize> {
    let test_count = tests.len();

    eprintln!(
        "\nrunning {} test{}",
        test_count,
        if test_count == 1 { "" } else { "s" },
    );

    let pass_count = tests.iter().filter(|case| run_one_test(&case)).count();
    let fail_count = (test_count - pass_count) as isize;

    eprintln!(
        "\ntest result: {}. {} passed; {} failed\n",
        if fail_count == 0 {
            GREEN_OK
        } else {
            RED_FAILED
        },
        pass_count,
        fail_count
    );

    Ok(fail_count)
}

fn run_one_test(test_case: &TestCase) -> bool {
    let test_name = test_case.name();
    let panic = panic::catch_unwind(|| test_case.func()()).is_err();

    if panic == test_case.should_panic() {
        eprintln!("test {} ... {}", test_name, GREEN_OK);
        true
    } else {
        eprintln!("test {} ... {}", test_name, RED_FAILED);
        false
    }
}

inventory::collect!(TestCase);

#[derive(Debug)]
pub struct TestCase {
    name: String,
    func: fn() -> (),
    should_panic: bool,
}

impl TestCase {
    pub fn new(name: String, func: fn() -> (), should_panic: bool) -> Self {
        Self {
            name,
            func,
            should_panic,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn func(&self) -> fn() -> () {
        self.func
    }

    pub fn should_panic(&self) -> bool {
        self.should_panic
    }
}

// To add a new test, define a new function with the type `fn() -> ()` and add `#[occlum_test]`
// attribute for it. Rust built-in attribute `#[should_panic]` without optional parameter is also
// supported.

mod tests {
    use super::*;

    #[occlum_test]
    #[should_panic]
    fn test_should_panic() {
        panic!();
    }
}
