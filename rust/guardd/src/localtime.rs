//! The host's local time, the way Python's `time.localtime` sees it.

/// Broken-down local time for `epoch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalTime {
    pub year: i32,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    /// Monday = 0, like Python's `tm_wday`.
    pub weekday: u32,
    /// Seconds east of UTC.
    pub offset: i64,
}

#[cfg(unix)]
pub fn local(epoch: i64) -> LocalTime {
    let t: libc::time_t = epoch as libc::time_t;
    // SAFETY: localtime_r writes only into the zeroed tm we own.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let ok = unsafe { !libc::localtime_r(&t, &mut tm).is_null() };
    if !ok {
        return utc(epoch);
    }
    LocalTime {
        year: tm.tm_year + 1900,
        month: (tm.tm_mon + 1) as u32,
        day: tm.tm_mday as u32,
        hour: tm.tm_hour as u32,
        minute: tm.tm_min as u32,
        weekday: ((tm.tm_wday + 6) % 7) as u32,
        offset: tm.tm_gmtoff as i64,
    }
}

#[cfg(not(unix))]
pub fn local(epoch: i64) -> LocalTime {
    utc(epoch)
}

pub fn utc(epoch: i64) -> LocalTime {
    let days = epoch.div_euclid(86400);
    let secs = epoch.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    LocalTime {
        year: y as i32,
        month: m as u32,
        day: d as u32,
        hour: (secs / 3600) as u32,
        minute: ((secs % 3600) / 60) as u32,
        weekday: ((days + 3).rem_euclid(7)) as u32,
        offset: 0,
    }
}

pub fn offset_at(epoch: i64) -> i64 {
    local(epoch).offset
}

pub fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// ISO year and week of a local date (`%G-W%V`).
pub fn iso_week(t: &LocalTime) -> String {
    let days = crate::context::days_from_civil(i64::from(t.year), i64::from(t.month), i64::from(t.day));
    // Thursday of this ISO week decides its year.
    let thursday = days - i64::from(t.weekday) + 3;
    let (ty, _, _) = civil_from_days(thursday);
    let jan1 = crate::context::days_from_civil(ty, 1, 1);
    let week = (thursday - jan1) / 7 + 1;
    format!("{ty:04}-W{week:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_breakdown_and_iso_week() {
        // 2026-11-23 is a Monday.
        let t = utc(1_795_392_000);
        assert_eq!((t.year, t.month, t.day, t.weekday), (2026, 11, 23, 0));
        assert_eq!(iso_week(&t), "2026-W48");
        let jan = utc(1_767_225_600); // 2026-01-01, a Thursday
        assert_eq!(jan.weekday, 3);
        assert_eq!(iso_week(&jan), "2026-W01");
    }
}
