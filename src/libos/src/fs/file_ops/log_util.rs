use super::*;

const MAX_PRINT_LEN: usize = 20;

pub fn detail_debug_print(
    ops: &str,
    fd: FileDesc,
    buf: Option<&[u8]>,
    len: Option<usize>,
) -> Result<()> {
    let mut result_str = Default::default();
    let is_read = if ops == "read" { true } else { false };

    let path = get_abs_path_by_fd(fd);
    if path.is_ok() {
        result_str = format!("{}: fd file path: {:?}", ops, path.unwrap());
    } else if let Ok(channel) = current!().file(fd)?.channel_uid() {
        // pipe
        result_str = format!("{}: fd channel uid: {}", ops, channel);
    } else {
        // TODO: Support other file type
        return Ok(());
    }

    debug!("{}", &result_str);
    if buf == None && len == None {
        return Ok(());
    }

    result_str.clear();
    let len = len.unwrap();
    let buf = buf.unwrap();
    let content = String::from_utf8_lossy(&buf[..len]);
    if len <= MAX_PRINT_LEN {
        result_str.push_str(&format!("{}: buf = {:?}", ops, content));
    } else {
        result_str.push_str(&format!(
            "{}: buf = {:?} ...",
            ops,
            &content[..MAX_PRINT_LEN]
        ));
    }

    debug!("{}", &result_str);
    Ok(())
}
