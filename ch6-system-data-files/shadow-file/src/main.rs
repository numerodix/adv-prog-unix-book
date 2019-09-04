use libc;
use std::ffi::{CStr, CString};


#[derive(Debug)]
struct ShadowEntry {
    username: String,
    password: String,
    last_pass_change: i64,
    min_days_between_changes: i64,
    max_days_between_changes: i64,
    warn_days_before_change: i64,
    days_until_inactive: i64,
    day_account_expires: i64,
    flag: u64,
}

fn get_cstr(ptr: *const libc::c_char) -> String {
    let cstr = unsafe { CStr::from_ptr(ptr) };
    cstr.to_str().unwrap().to_string()
}

fn parse_spwd(sp: *const libc::spwd) -> ShadowEntry {
    unsafe {
        let username = get_cstr((*sp).sp_namp);
        let password = get_cstr((*sp).sp_pwdp);

        ShadowEntry {
            username,
            password,
            last_pass_change: (*sp).sp_lstchg,
            min_days_between_changes: (*sp).sp_min,
            max_days_between_changes: (*sp).sp_max,
            warn_days_before_change: (*sp).sp_warn,
            days_until_inactive: (*sp).sp_inact,
            day_account_expires: (*sp).sp_expire,
            flag: (*sp).sp_flag,
        }
    }
}

fn main() {
    // getspnam
    let cstr_root = CString::new("root").unwrap().into_raw();
    let user_root_c = unsafe { libc::getspnam(cstr_root) };
    assert!(!user_root_c.is_null(), "Could not load entry - are you running as root?");

    let user_root = parse_spwd(user_root_c);
    println!("{:#?}", user_root);
}