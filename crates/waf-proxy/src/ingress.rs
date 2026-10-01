//! Validate original HTTP/1 framing before a parser can discard ambiguous headers.
use http::StatusCode;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf},
    net::UnixStream,
    time::timeout,
};
pub struct BufferedStream {
    stream: UnixStream,
    prefix: Vec<u8>,
    offset: usize,
}
impl AsyncRead for BufferedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset < self.prefix.len() {
            let count = buf.remaining().min(self.prefix.len() - self.offset);
            buf.put_slice(&self.prefix[self.offset..self.offset + count]);
            self.offset += count;
            if self.offset == self.prefix.len() {
                self.prefix.clear();
                self.prefix.shrink_to_fit();
            }
            Poll::Ready(Ok(()))
        } else {
            Pin::new(&mut self.stream).poll_read(cx, buf)
        }
    }
}
impl AsyncWrite for BufferedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
pub struct HeadError {
    pub status: StatusCode,
    pub reason: &'static str,
}
fn bad(reason: &'static str) -> HeadError {
    HeadError {
        status: StatusCode::BAD_REQUEST,
        reason,
    }
}
pub async fn validate(
    stream: &mut UnixStream,
    max_bytes: usize,
    max_count: usize,
    seconds: u64,
) -> Result<Vec<u8>, HeadError> {
    let read = async {
        let mut prefix = Vec::new();
        let mut chunk = [0u8; 1024];
        let end = loop {
            if let Some(position) = prefix.windows(4).position(|w| w == b"\r\n\r\n") {
                break position + 4;
            }
            if prefix.len() >= max_bytes {
                return Err(HeadError {
                    status: StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                    reason: "raw_header_limit",
                });
            }
            let count = stream
                .read(&mut chunk)
                .await
                .map_err(|_| bad("raw_header_read_error"))?;
            if count == 0 {
                return Err(bad("incomplete_headers"));
            }
            prefix.extend_from_slice(&chunk[..count]);
        };
        if end > max_bytes {
            return Err(HeadError {
                status: StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                reason: "raw_header_limit",
            });
        }
        let mut headers = vec![httparse::EMPTY_HEADER; max_count];
        let mut request = httparse::Request::new(&mut headers);
        request
            .parse(&prefix[..end])
            .map_err(|_| bad("invalid_raw_headers"))?;
        let has = |name: &str| {
            request
                .headers
                .iter()
                .any(|h| h.name.eq_ignore_ascii_case(name))
        };
        if has("content-length") && has("transfer-encoding") {
            return Err(bad("ambiguous_raw_framing"));
        }
        for name in [
            "host",
            "content-length",
            "transfer-encoding",
            "content-type",
            "content-encoding",
            "x-waf-client-ip",
            "x-waf-admin-friend",
            "x-http-method-override",
        ] {
            if request
                .headers
                .iter()
                .filter(|h| h.name.eq_ignore_ascii_case(name))
                .count()
                > 1
            {
                return Err(bad("duplicate_raw_singleton"));
            }
        }
        Ok(prefix)
    };
    timeout(Duration::from_secs(seconds), read)
        .await
        .map_err(|_| HeadError {
            status: StatusCode::REQUEST_TIMEOUT,
            reason: "header_timeout",
        })?
}
pub fn replay(stream: UnixStream, prefix: Vec<u8>) -> BufferedStream {
    BufferedStream {
        stream,
        prefix,
        offset: 0,
    }
}
