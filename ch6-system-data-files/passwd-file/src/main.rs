use itertools::Itertools;
use libc;
use std::ffi::{CStr, CString};


#[derive(Debug)]
struct PasswdEntry {
    username: String,
    password: String,
    uid: u32,
    gid: u32,
    comment: String,
    working_dir: String,
    shell: String,
}


fn get_cstr(ptr: *mut libc::c_char) -> String {
    let cstr = unsafe { CStr::from_ptr(ptr) };
    cstr.to_str().unwrap().to_string()
}

fn parse_passwd(pw: *const libc::passwd) -> PasswdEntry {
    unsafe {
        let username = get_cstr((*pw).pw_name);
        let password = get_cstr((*pw).pw_passwd);
        let comment = get_cstr((*pw).pw_gecos);
        let working_dir = get_cstr((*pw).pw_dir);
        let shell = get_cstr((*pw).pw_shell);

        PasswdEntry {
            username,
            password,
            uid: (*pw).pw_uid,
            gid: (*pw).pw_gid,
            comment,
            working_dir,
            shell,
        }
    }
}

fn load_all_entries() -> Vec<PasswdEntry> {
    let mut entries = vec![];

    unsafe {
        // rewind the iterator
        libc::setpwent();

        loop {
            // read the next entry
            let entry_c = libc::getpwent();

            if entry_c.is_null() {
                break
            }

            let entry = parse_passwd(entry_c);
            entries.push(entry);
        }

        // close the iterator
        libc::endpwent();
    }

    entries
}

fn main() {
    // getpwuid
    let user_0_c = unsafe { libc::getpwuid(0) };
    let user_0 = parse_passwd(user_0_c);
    println!("{:#?}", user_0);

    let user_1000_c = unsafe { libc::getpwuid(1000) };
    let user_1000 = parse_passwd(user_1000_c);
    println!("{:#?}", user_1000);

    // getpwnam
    let cstr_root = CString::new("root").unwrap().into_raw();
    let user_root_c = unsafe { libc::getpwnam(cstr_root) };
    let user_root = parse_passwd(user_root_c);
    println!("{:#?}", user_root);

    let cstr_sshd = CString::new("sshd").unwrap().into_raw();
    let user_sshd_c = unsafe { libc::getpwnam(cstr_sshd) };
    let user_sshd = parse_passwd(user_sshd_c);
    println!("{:#?}", user_sshd);

    // getpwent
    let entries = load_all_entries();
    let usernames = entries.iter().map(|e| &e.username).collect::<Vec<_>>();
    println!("All users: {}", usernames.iter().join(", "));
}