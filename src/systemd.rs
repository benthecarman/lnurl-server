//! Service manager integration via the `sd_notify(3)` protocol.
//!
//! Every function here is a no-op unless systemd started the process as a
//! `Type=notify` unit (`NOTIFY_SOCKET` is set), so the server behaves the
//! same when started by hand or inside a container.

#[cfg(unix)]
use sd_notify::NotifyState;

/// Tells systemd the service is ready to accept requests.
///
/// With `Type=notify`, `systemctl start` blocks and units ordered after this
/// one wait until this message is sent.
///
/// # Parameters
/// * `status` - Human readable status line shown by `systemctl status`
pub fn notify_ready(status: &str) {
    #[cfg(unix)]
    notify(&[NotifyState::Ready, NotifyState::Status(status)]);
    #[cfg(not(unix))]
    let _ = status;
}

/// Tells systemd the service has started shutting down.
pub fn notify_stopping() {
    #[cfg(unix)]
    notify(&[NotifyState::Stopping]);
}

/// Pings the systemd watchdog for the life of the process if the unit sets
/// `WatchdogSec=`.
///
/// Pings are sent at half the configured timeout, as `sd_watchdog_enabled(3)`
/// recommends. The ping task runs on the tokio runtime, so if the runtime
/// stops making progress the pings stop and systemd kills and restarts the
/// service.
pub fn spawn_watchdog() {
    #[cfg(unix)]
    {
        let Some(timeout) = sd_notify::watchdog_enabled() else {
            return;
        };
        let interval = timeout / 2;
        if interval.is_zero() {
            eprintln!("Ignoring systemd watchdog, timeout {timeout:?} is too short");
            return;
        }
        println!("systemd watchdog enabled, pinging every {interval:?}");
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                notify(&[NotifyState::Watchdog]);
            }
        });
    }
}

#[cfg(unix)]
fn notify(state: &[NotifyState]) {
    // sd_notify::notify returns Ok(()) when NOTIFY_SOCKET is unset, so an
    // error here means systemd expects a message that did not arrive
    if let Err(e) = sd_notify::notify(state) {
        eprintln!("Failed to notify systemd: {e}");
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::net::UnixDatagram;

    /// Receives one datagram and splits it into its `KEY=VALUE` lines.
    async fn recv(sock: &UnixDatagram) -> Vec<String> {
        let mut buf = [0u8; 256];
        let n = tokio::time::timeout(Duration::from_secs(5), sock.recv(&mut buf))
            .await
            .expect("timed out waiting for a notification")
            .expect("failed to receive notification");
        String::from_utf8_lossy(&buf[..n])
            .lines()
            .map(str::to_owned)
            .collect()
    }

    // Stands in for systemd with a datagram socket. Kept as a single test
    // because it configures process wide environment variables.
    #[tokio::test]
    async fn notifies_fake_systemd() {
        let path = std::env::temp_dir().join(format!(
            "lnurl-server-sd-notify-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let sock = UnixDatagram::bind(&path).expect("failed to bind notify socket");
        std::env::set_var("NOTIFY_SOCKET", &path);

        notify_ready("serving");
        assert_eq!(recv(&sock).await, ["READY=1", "STATUS=serving"]);

        notify_stopping();
        assert_eq!(recv(&sock).await, ["STOPPING=1"]);

        // 200ms timeout, so a ping every 100ms
        std::env::set_var("WATCHDOG_USEC", "200000");
        std::env::set_var("WATCHDOG_PID", std::process::id().to_string());
        spawn_watchdog();
        assert_eq!(recv(&sock).await, ["WATCHDOG=1"]);
        assert_eq!(recv(&sock).await, ["WATCHDOG=1"]);

        let _ = std::fs::remove_file(&path);
    }
}
