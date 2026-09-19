use std::ffi::{CStr, CString, c_char, c_int};
use std::os::unix::process::CommandExt;
use std::process::Command;

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

/// Most `(param "NAME")` pairs a profile may take.
const MAX_PARAMS: usize = 8;

/// Like [`sandboxed`], but with caller-supplied SBPL text and parameters.
///
/// # Panics
///
/// If more than `MAX_PARAMS` parameters are given, or if any string contains
/// an interior NULL.
pub fn spawn_with_profile(profile: &str, program: &str, params: &[(&str, &str)]) -> Command {
    assert!(params.len() <= MAX_PARAMS);
    let profile = CString::new(profile).unwrap();
    let owned: Vec<CString> = params
        .iter()
        .flat_map(|(k, v)| [CString::new(*k).unwrap(), CString::new(*v).unwrap()])
        .collect();

    let mut cmd = Command::new(program);
    unsafe {
        cmd.pre_exec(move || {
            // Fixed-size stack array: the forked child must not allocate.
            let mut ptrs: [*const c_char; 2 * MAX_PARAMS + 1] =
                [std::ptr::null(); 2 * MAX_PARAMS + 1];
            for (slot, s) in ptrs.iter_mut().zip(&owned) {
                *slot = s.as_ptr();
            }
            apply(&profile, &ptrs).map_err(std::io::Error::other)
        });
    }
    cmd
}
