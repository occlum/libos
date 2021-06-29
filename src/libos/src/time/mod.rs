use self::timer_slack::*;
use super::*;
use core::convert::TryFrom;
use process::pid_t;
use rcore_fs::dev::TimeProvider;
use rcore_fs::vfs::Timespec;
use std::time::Duration;
use std::{fmt, u64};
use syscall::SyscallNum;

mod profiler;
pub mod timer_slack;
pub mod up_time;

pub use profiler::ThreadProfiler;
pub use timer_slack::TIMERSLACK;

#[allow(non_camel_case_types)]
pub type time_t = i64;

#[allow(non_camel_case_types)]
pub type suseconds_t = i64;

#[allow(non_camel_case_types)]
pub type clock_t = i64;

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct timeval_t {
    sec: time_t,
    usec: suseconds_t,
}

impl timeval_t {
    pub fn new(sec: time_t, usec: suseconds_t) -> Self {
        let time = Self { sec, usec };

        time.validate().unwrap();
        time
    }

    pub fn validate(&self) -> Result<()> {
        if self.sec >= 0 && self.usec >= 0 && self.usec < 1_000_000 {
            Ok(())
        } else {
            return_errno!(EINVAL, "invalid value for timeval_t");
        }
    }

    pub fn as_duration(&self) -> Duration {
        Duration::new(self.sec as u64, (self.usec * 1_000) as u32)
    }
}

impl From<Duration> for timeval_t {
    fn from(duration: Duration) -> timeval_t {
        let sec = duration.as_secs() as time_t;
        let usec = duration.subsec_micros() as i64;
        debug_assert!(sec >= 0); // nsec >= 0 always holds
        timeval_t { sec, usec }
    }
}

pub fn do_gettimeofday() -> timeval_t {
    extern "C" {
        fn occlum_ocall_gettimeofday(tv: *mut timeval_t) -> sgx_status_t;
    }

    let mut tv: timeval_t = Default::default();
    unsafe {
        occlum_ocall_gettimeofday(&mut tv as *mut timeval_t);
    }
    tv.validate().expect("ocall returned invalid timeval_t");
    tv
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct timespec_t {
    sec: time_t,
    nsec: i64,
}

impl From<Duration> for timespec_t {
    fn from(duration: Duration) -> timespec_t {
        let sec = duration.as_secs() as time_t;
        let nsec = duration.subsec_nanos() as i64;
        debug_assert!(sec >= 0); // nsec >= 0 always holds
        timespec_t { sec, nsec }
    }
}

impl timespec_t {
    pub fn from_raw_ptr(ptr: *const timespec_t) -> Result<timespec_t> {
        let ts = unsafe { *ptr };
        ts.validate()?;
        Ok(ts)
    }

    pub fn validate(&self) -> Result<()> {
        if self.sec >= 0 && self.nsec >= 0 && self.nsec < 1_000_000_000 {
            Ok(())
        } else {
            return_errno!(EINVAL, "invalid value for timespec_t");
        }
    }

    pub fn sec(&self) -> time_t {
        self.sec
    }

    pub fn nsec(&self) -> i64 {
        self.nsec
    }

    pub fn as_duration(&self) -> Duration {
        Duration::new(self.sec as u64, self.nsec as u32)
    }
}

#[allow(non_camel_case_types)]
pub type clockid_t = i32;

#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum ClockID {
    CLOCK_REALTIME = 0,
    CLOCK_MONOTONIC = 1,
    CLOCK_PROCESS_CPUTIME_ID = 2,
    CLOCK_THREAD_CPUTIME_ID = 3,
    CLOCK_MONOTONIC_RAW = 4,
    CLOCK_REALTIME_COARSE = 5,
    CLOCK_MONOTONIC_COARSE = 6,
    CLOCK_BOOTTIME = 7,
}

impl ClockID {
    #[deny(unreachable_patterns)]
    pub fn from_raw(clockid: clockid_t) -> Result<ClockID> {
        Ok(match clockid as i32 {
            0 => ClockID::CLOCK_REALTIME,
            1 => ClockID::CLOCK_MONOTONIC,
            2 => ClockID::CLOCK_PROCESS_CPUTIME_ID,
            3 => ClockID::CLOCK_THREAD_CPUTIME_ID,
            4 => ClockID::CLOCK_MONOTONIC_RAW,
            5 => ClockID::CLOCK_REALTIME_COARSE,
            6 => ClockID::CLOCK_MONOTONIC_COARSE,
            7 => ClockID::CLOCK_BOOTTIME,
            _ => return_errno!(EINVAL, "invalid command"),
        })
    }
}

pub fn do_clock_gettime(clockid: ClockID) -> Result<timespec_t> {
    extern "C" {
        fn occlum_ocall_clock_gettime(clockid: clockid_t, tp: *mut timespec_t) -> sgx_status_t;
    }

    let mut tv: timespec_t = Default::default();
    unsafe {
        occlum_ocall_clock_gettime(clockid as clockid_t, &mut tv as *mut timespec_t);
    }
    tv.validate().expect("ocall returned invalid timespec");
    Ok(tv)
}

pub fn do_clock_getres(clockid: ClockID) -> Result<timespec_t> {
    extern "C" {
        fn occlum_ocall_clock_getres(clockid: clockid_t, res: *mut timespec_t) -> sgx_status_t;
    }

    let mut res: timespec_t = Default::default();
    unsafe {
        occlum_ocall_clock_getres(clockid as clockid_t, &mut res as *mut timespec_t);
    }
    let validate_resolution = |res: &timespec_t| -> Result<()> {
        // The resolution can be ranged from 1 nanosecond to a few milliseconds
        if res.sec == 0 && res.nsec > 0 && res.nsec < 1_000_000_000 {
            Ok(())
        } else {
            return_errno!(EINVAL, "invalid value for resolution");
        }
    };
    // do sanity check
    validate_resolution(&res).expect("ocall returned invalid resolution");
    Ok(res)
}

pub fn do_nanosleep(req: &timespec_t, rem: Option<&mut timespec_t>) -> Result<()> {
    extern "C" {
        fn occlum_ocall_nanosleep(
            ret: *mut i32,
            req: *const timespec_t,
            rem: *mut timespec_t,
        ) -> sgx_status_t;
    }
    unsafe {
        let mut ret = 0;
        let mut u_rem: timespec_t = timespec_t { sec: 0, nsec: 0 };
        let sgx_status = occlum_ocall_nanosleep(&mut ret, req, &mut u_rem);
        assert!(sgx_status == sgx_status_t::SGX_SUCCESS);
        assert!(ret == 0 || libc::errno() == Errno::EINTR as i32);
        if ret != 0 {
            assert!(u_rem.as_duration() <= req.as_duration() + (*TIMERSLACK).to_duration());
            if let Some(rem) = rem {
                *rem = u_rem;
            }
            return_errno!(EINTR, "sleep interrupted");
        }
    }
    Ok(())
}

pub fn do_thread_getcpuclock() -> Result<timespec_t> {
    extern "C" {
        fn occlum_ocall_thread_getcpuclock(ret: *mut c_int, tp: *mut timespec_t) -> sgx_status_t;
    }

    let mut tv: timespec_t = Default::default();
    try_libc!({
        let mut retval: i32 = 0;
        let status = occlum_ocall_thread_getcpuclock(&mut retval, &mut tv as *mut timespec_t);
        assert!(status == sgx_status_t::SGX_SUCCESS);
        retval
    });
    tv.validate()?;
    Ok(tv)
}

pub fn do_rdtsc() -> (u32, u32) {
    extern "C" {
        fn occlum_ocall_rdtsc(low: *mut u32, high: *mut u32) -> sgx_status_t;
    }
    let mut low = 0;
    let mut high = 0;
    let sgx_status = unsafe { occlum_ocall_rdtsc(&mut low, &mut high) };
    assert!(sgx_status == sgx_status_t::SGX_SUCCESS);
    (low, high)
}

// For SEFS
pub struct OcclumTimeProvider;

impl TimeProvider for OcclumTimeProvider {
    fn current_time(&self) -> Timespec {
        let time = do_gettimeofday();
        Timespec {
            sec: time.sec,
            nsec: time.usec as i32 * 1000,
        }
    }
}

// For Timerfd
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
#[allow(non_camel_case_types)]

pub struct itimerspec_t {
    it_interval: timespec_t,
    it_value: timespec_t,
}

impl itimerspec_t {
    pub fn new(interval: timespec_t, value: timespec_t) -> Self {
        Self {
            it_interval: interval,
            it_value: value,
        }
    }
}
