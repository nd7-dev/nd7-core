use std::ffi::{CStr, CString, c_char, c_int};
use std::os::unix::process::CommandExt;
use std::process::Command;

const PROFILE: &str = include_str!("claude.sb");

#[link(name = "sandbox")]
unsafe extern "C" {
    unsafe fn sandbox_init_with_parameters(
        profile: *const c_char,
        flags: u64,
        params: *const *const c_char,
        errorbuf: *mut *mut c_char,
    ) -> c_int;
    unsafe fn sandbox_free_error(errorbuf: *mut c_char);
}

/// Applies profile to the calling process. Irreversible.
fn apply(profile: &CStr, params: &[*const c_char]) -> Result<(), String> {
    let mut err: *mut c_char = std::ptr::null_mut();
    let rc =
        unsafe { sandbox_init_with_parameters(profile.as_ptr(), 0, params.as_ptr(), &mut err) };
    if rc == 0 {
        // init sandbox succeeded
        return Ok(());
    }
    // init sandbox failed
    if !err.is_null() {
        let msg = unsafe { CStr::from_ptr(err) }
            .to_string_lossy()
            .into_owned();

        unsafe { sandbox_free_error(err) };
        return Err(msg);
    }
    // init sandbox failed, and error failed as well. Should not happen in practice.
    Err("failed to init sandbox. Sandbox failed silently".into())
}

pub fn sandboxed(program: &str, project: &str, tmp: &str, home: &str) -> Command {
    let profile = CString::new(PROFILE).unwrap();
    let owned: Vec<CString> = [("PROJ", project), ("TMP", tmp), ("HOME", home)]
        .iter()
        .flat_map(|(k, v)| [CString::new(*k).unwrap(), CString::new(*v).unwrap()])
        .collect();

    let mut cmd = Command::new(program);
    unsafe {
        cmd.pre_exec(move || {
            let mut ptrs: [*const c_char; 7] = [std::ptr::null(); 7];
            for (slot, s) in ptrs.iter_mut().zip(&owned) {
                *slot = s.as_ptr();
            }
            apply(&profile, &ptrs).map_err(std::io::Error::other)
        });
    }
    cmd
}
