//! The hostile-request table for the share file server. Each safety rule in `sharefs.rs` has a
//! test here that fails when the rule is broken.

use super::*;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::sync::atomic::{AtomicBool, Ordering};
use wsh_client::share::ShareProvider;

struct Fx {
    _tmp: tempfile::TempDir,
    /// The shared directory.
    root: PathBuf,
    /// A directory next to it that must never be reached.
    outside: PathBuf,
    srv: ShareServer,
}

fn limits() -> Limits {
    Limits {
        max_handles: 4,
        max_bytes: 4096,
        page_entries: 5,
        max_dir_entries: 50,
        // No throttling unless a test asks.
        bytes_per_sec: 0,
        ..Limits::default()
    }
}

fn fx_with(writable: bool, limits: Limits) -> Fx {
    let tmp = tempfile::tempdir().expect("tempdir");
    let base = std::fs::canonicalize(tmp.path()).expect("canon");
    let root = base.join("share");
    let outside = base.join("outside");
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("secret.txt"), b"TOP SECRET").unwrap();
    let share = Share::open(&ShareSpec {
        name: "s".into(),
        path: root.clone(),
        writable,
    })
    .expect("open share");
    Fx {
        srv: ShareServer::new(vec![share], limits),
        _tmp: tmp,
        root,
        outside,
    }
}

fn fx(writable: bool) -> Fx {
    fx_with(writable, limits())
}

fn rq(op: &str) -> ShareRequestPayload {
    ShareRequestPayload {
        request_id: 1,
        share: "s".into(),
        op: op.into(),
        path: None,
        to: None,
        handle: None,
        offset: None,
        length: None,
        mode: None,
        flags: vec![],
        cursor: None,
        attr: Value::Null,
        data: None,
    }
}

fn at(op: &str, path: &str) -> ShareRequestPayload {
    ShareRequestPayload {
        path: Some(path.into()),
        ..rq(op)
    }
}

fn open_req(path: &str, flags: &[&str]) -> ShareRequestPayload {
    ShareRequestPayload {
        flags: flags.iter().map(|s| s.to_string()).collect(),
        ..at("open", path)
    }
}

impl Fx {
    fn run(&self, r: ShareRequestPayload) -> Result<ShareReplyPayload, ShareError> {
        self.srv.exec(&r)
    }
    fn errno(&self, r: ShareRequestPayload) -> &'static str {
        match self.run(r) {
            Ok(_) => "OK",
            Err(e) => e.errno,
        }
    }
    fn names(&self, path: &str) -> Vec<String> {
        let rep = self.run(at("readdir", path)).expect("readdir");
        rep.entries
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["name"].as_str().unwrap().to_string())
            .collect()
    }
    /// Read a whole file through the share.
    fn cat(&self, path: &str) -> Result<Vec<u8>, ShareError> {
        let o = self.run(open_req(path, &["read"]))?;
        let h = o.handle.unwrap();
        let mut out = Vec::new();
        loop {
            let r = self.run(ShareRequestPayload {
                handle: Some(h),
                offset: Some(out.len() as u64),
                length: Some(1024),
                ..rq("read")
            })?;
            out.extend(r.data.unwrap());
            if r.eof == Some(true) {
                break;
            }
        }
        self.run(ShareRequestPayload {
            handle: Some(h),
            ..rq("close")
        })?;
        Ok(out)
    }
}

// ── command line ──────────────────────────────────────────────────

#[test]
fn spec_parsing() {
    let s = parse_spec("src=/tmp/x").unwrap();
    assert_eq!((s.name.as_str(), s.writable), ("src", false));
    assert!(!parse_spec("a=/x:ro").unwrap().writable);
    assert!(parse_spec("a=/x:rw").unwrap().writable);
    assert_eq!(parse_spec("a=/x:rw").unwrap().path, PathBuf::from("/x"));
    assert!(parse_spec("a=relative/dir").is_err(), "must be absolute");
    assert!(parse_spec("/x").is_err(), "needs a name");
    assert!(parse_spec("a b=/x").is_err());
    assert!(parse_spec("=/x").is_err());
    assert!(parse_spec(&format!("{}=/x", "n".repeat(65))).is_err());
}

#[test]
fn a_missing_or_non_directory_root_is_an_error_before_anything_is_offered() {
    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join("f");
    std::fs::write(&file, b"x").unwrap();
    for p in [tmp.path().join("nope"), file] {
        let r = Share::open(&ShareSpec {
            name: "s".into(),
            path: p,
            writable: false,
        });
        assert!(r.is_err());
    }
}

// ── listing and reading ───────────────────────────────────────────

#[test]
fn readdir_carries_attributes_sorted_and_pages_without_gaps() {
    let f = fx(false);
    for i in 0..12 {
        std::fs::write(f.root.join(format!("f{i:02}")), vec![b'x'; i]).unwrap();
    }
    std::fs::create_dir(f.root.join("dir")).unwrap();
    let first = f.run(at("readdir", "")).unwrap();
    let e = first.entries.as_array().unwrap();
    assert_eq!(e.len(), 5, "one page is page_entries");
    assert_eq!(e[0]["name"], "dir");
    assert_eq!(e[0]["type"], "directory");
    assert_eq!(e[2]["type"], "file");
    assert_eq!(e[2]["size"], 1);
    assert!(e[2]["mtime_ms"].as_f64().unwrap() > 0.0);
    let mut seen: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0;
    loop {
        let r = f
            .run(ShareRequestPayload {
                cursor: cursor.clone(),
                ..at("readdir", "/")
            })
            .unwrap();
        seen.extend(
            r.entries
                .as_array()
                .unwrap()
                .iter()
                .map(|e| e["name"].as_str().unwrap().to_string()),
        );
        pages += 1;
        cursor = r.cursor;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(seen.len(), 13);
    assert_eq!(pages, 3);
    let mut sorted = seen.clone();
    sorted.sort();
    assert_eq!(seen, sorted);
    sorted.dedup();
    assert_eq!(sorted.len(), 13, "no entry twice across pages");
}

#[test]
fn a_symlink_is_listed_as_a_symlink_with_its_target_and_never_followed() {
    let f = fx(false);
    symlink(&f.outside, f.root.join("abs-out")).unwrap();
    symlink("../outside/secret.txt", f.root.join("rel-out")).unwrap();
    symlink("nothing", f.root.join("dangling")).unwrap();
    let rep = f.run(at("readdir", "")).unwrap();
    let by: HashMap<_, _> = rep
        .entries
        .as_array()
        .unwrap()
        .iter()
        .map(|e| (e["name"].as_str().unwrap().to_string(), e.clone()))
        .collect();
    assert_eq!(by["abs-out"]["type"], "symlink");
    assert_eq!(by["rel-out"]["target"], "../outside/secret.txt");
    // stat of a symlink is the symlink's own; reading through one is refused.
    assert_eq!(f.run(at("stat", "rel-out")).unwrap().attr["type"], "symlink");
    assert_eq!(f.errno(open_req("rel-out", &["read"])), "ELOOP");
    assert_eq!(f.errno(open_req("abs-out/secret.txt", &["read"])), "ELOOP");
    assert_eq!(f.errno(at("readdir", "abs-out")), "ELOOP");
    assert_eq!(f.errno(at("stat", "abs-out/secret.txt")), "ELOOP");
    assert_eq!(
        f.run(at("readlink", "rel-out")).unwrap().target.unwrap(),
        "../outside/secret.txt"
    );
}

#[test]
fn small_files_come_with_the_open_and_large_ones_do_not() {
    let f = fx(false);
    std::fs::write(f.root.join("small"), b"hello").unwrap();
    std::fs::write(f.root.join("big"), vec![7u8; 3000]).unwrap();
    let o = f
        .run(ShareRequestPayload {
            length: Some(1024),
            ..open_req("small", &["read"])
        })
        .unwrap();
    assert_eq!(o.data.as_deref(), Some(&b"hello"[..]));
    assert_eq!(o.eof, Some(true));
    let o = f
        .run(ShareRequestPayload {
            length: Some(1024),
            ..open_req("big", &["read"])
        })
        .unwrap();
    assert!(o.data.is_none(), "bigger than asked: read it with `read`");
    assert_eq!(f.cat("big").unwrap(), vec![7u8; 3000]);
}

// ── escapes ───────────────────────────────────────────────────────

#[test]
fn dot_dot_is_refused_in_every_position() {
    let f = fx(false);
    std::fs::create_dir(f.root.join("d")).unwrap();
    for p in [
        "..",
        "../outside/secret.txt",
        "d/../../outside/secret.txt",
        "d/..",
        "./../outside",
        "d/./../..",
        "/../outside/secret.txt",
        "d/../d",
    ] {
        for op in ["stat", "readdir", "readlink"] {
            assert_eq!(f.errno(at(op, p)), "EINVAL", "{op} {p}");
        }
        assert_eq!(f.errno(open_req(p, &["read"])), "EINVAL", "open {p}");
    }
}

#[test]
fn an_absolute_path_means_a_path_under_the_root() {
    let f = fx(false);
    std::fs::write(f.outside.join("x"), b"x").unwrap();
    let abs = f.outside.join("secret.txt");
    assert_eq!(
        f.errno(open_req(abs.to_str().unwrap(), &["read"])),
        "ENOENT",
        "the host's idea of an absolute path is under the root, where it does not exist"
    );
}

#[test]
fn a_nul_byte_in_a_path_is_refused() {
    let f = fx(false);
    assert_eq!(f.errno(at("stat", "a\0b")), "EINVAL");
}

#[test]
fn a_symlink_in_the_middle_of_a_path_is_never_followed() {
    let f = fx(true);
    std::fs::create_dir(f.root.join("real")).unwrap();
    std::fs::write(f.root.join("real/ok.txt"), b"inside").unwrap();
    symlink("real", f.root.join("inlink")).unwrap(); // even a link that stays inside
    symlink(&f.outside, f.root.join("out")).unwrap();
    assert_eq!(f.cat("real/ok.txt").unwrap(), b"inside");
    assert_eq!(f.errno(at("stat", "inlink/ok.txt")), "ELOOP");
    assert_eq!(f.errno(open_req("out/secret.txt", &["read"])), "ELOOP");
    assert_eq!(
        f.errno(open_req("out/new", &["write", "create"])),
        "ELOOP"
    );
    assert_eq!(f.errno(at("mkdir", "out/d")), "ELOOP");
    assert_eq!(f.errno(at("unlink", "out/secret.txt")), "ELOOP");
    assert!(f.outside.join("secret.txt").exists());
    assert!(!f.outside.join("new").exists() && !f.outside.join("d").exists());
}

#[test]
fn a_symlink_swapped_in_between_the_check_and_the_use_is_not_followed() {
    // One thread flips `d` between a real directory holding inside.txt and a symlink to the
    // outside directory (which holds secret.txt); the other keeps opening `d/<name>`. Whatever
    // the interleaving, the secret must never come back.
    let f = fx(false);
    std::fs::write(f.outside.join("inside.txt"), b"OUTSIDE").unwrap();
    let real = f.root.join("d-real");
    std::fs::create_dir(&real).unwrap();
    std::fs::write(real.join("inside.txt"), b"inside").unwrap();
    let link = f.root.join("d");
    std::fs::rename(&real, &link).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let flipper = {
        let (root, outside, stop) = (f.root.clone(), f.outside.clone(), stop.clone());
        std::thread::spawn(move || {
            let d = root.join("d");
            let hold = root.join("d-hold");
            while !stop.load(Ordering::Relaxed) {
                // real dir -> aside, symlink in place; then back.
                if std::fs::rename(&d, &hold).is_err() {
                    continue;
                }
                let _ = symlink(&outside, &d);
                std::thread::sleep(Duration::from_micros(200));
                let _ = std::fs::remove_file(&d);
                let _ = std::fs::rename(&hold, &d);
            }
        })
    };
    let mut inside = 0;
    for _ in 0..3000 {
        match f.cat("d/inside.txt") {
            Ok(b) => {
                assert_eq!(b, b"inside", "a swapped-in symlink was followed");
                inside += 1;
            }
            Err(e) => assert!(
                matches!(e.errno, "ELOOP" | "ENOENT" | "ENOTDIR"),
                "unexpected {e:?}"
            ),
        }
    }
    stop.store(true, Ordering::Relaxed);
    flipper.join().unwrap();
    assert!(inside > 0, "the race never let a read through: not a test");
}

#[test]
fn a_symlink_planted_where_a_file_is_created_is_never_written_through() {
    let f = fx(true);
    let victim = f.outside.join("victim");
    std::fs::write(&victim, b"original").unwrap();
    symlink(&victim, f.root.join("planted")).unwrap();
    assert_eq!(f.errno(at("create", "planted")), "EEXIST");
    assert_eq!(f.errno(open_req("planted", &["write", "create"])), "ELOOP");
    assert_eq!(
        f.errno(open_req("planted", &["write", "create", "trunc"])),
        "ELOOP"
    );
    assert_eq!(f.errno(open_req("planted", &["write"])), "ELOOP");
    assert_eq!(
        f.errno(ShareRequestPayload {
            attr: json!({"size": 0}),
            ..at("setattr", "planted")
        }),
        "ELOOP"
    );
    assert_eq!(
        f.errno(ShareRequestPayload {
            attr: json!({"mode": 0o777}),
            ..at("setattr", "planted")
        }),
        "ELOOP"
    );
    assert_eq!(std::fs::read(&victim).unwrap(), b"original");
    assert_eq!(
        std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777,
        0o644
    );
}

#[test]
fn unlinking_a_symlink_removes_the_link_and_not_its_target() {
    let f = fx(true);
    symlink(f.outside.join("secret.txt"), f.root.join("l")).unwrap();
    f.run(at("unlink", "l")).unwrap();
    assert!(std::fs::symlink_metadata(f.root.join("l")).is_err());
    assert!(f.outside.join("secret.txt").exists());
}

#[test]
fn renaming_cannot_leave_the_share() {
    let f = fx(true);
    std::fs::write(f.root.join("a"), b"a").unwrap();
    let mv = |from: &str, to: &str| {
        f.errno(ShareRequestPayload {
            to: Some(to.into()),
            ..at("rename", from)
        })
    };
    assert_eq!(mv("a", "../outside/a"), "EINVAL");
    assert_eq!(mv("../outside/secret.txt", "a"), "EINVAL");
    symlink(&f.outside, f.root.join("out")).unwrap();
    assert_eq!(mv("a", "out/a"), "ELOOP");
    assert_eq!(mv("", "x"), "EINVAL", "the root itself cannot be renamed");
    assert!(f.outside.join("secret.txt").exists());
    assert_eq!(mv("a", "b"), "OK");
    assert!(f.root.join("b").exists() && !f.root.join("a").exists());
}

#[test]
fn case_tricks_do_not_reach_the_outside() {
    // On a case-insensitive volume (macOS) `LINK` is the symlink `link`; on a case-sensitive one
    // it is a name that does not exist. Neither may open the secret, because confinement is by
    // descriptor and O_NOFOLLOW, not by comparing strings.
    let f = fx(false);
    symlink(&f.outside, f.root.join("link")).unwrap();
    for p in [
        "link/secret.txt",
        "LINK/secret.txt",
        "Link/SECRET.TXT",
        "link/./secret.txt",
        "lInK",
    ] {
        let r = f.run(open_req(p, &["read"]));
        assert!(r.is_err(), "{p} opened something");
    }
    assert_eq!(f.errno(at("stat", "link/../Link")), "EINVAL");
}

#[test]
fn a_directory_on_another_file_system_is_not_entered() {
    // /dev is a different device than a temp directory on every unix we build for.
    let f = fx(false);
    let mount = f.root.join("mnt");
    std::fs::create_dir(&mount).unwrap();
    // Cannot mount in a test: emulate by pointing the share at /dev's parent check instead.
    let dev_meta = std::fs::metadata("/dev").unwrap();
    let share_meta = std::fs::metadata(&f.root).unwrap();
    if dev_meta.dev() == share_meta.dev() {
        return;
    }
    let share = Share::open(&ShareSpec {
        name: "s".into(),
        path: "/".into(),
        writable: false,
    })
    .unwrap();
    let srv = ShareServer::new(vec![share], limits());
    // `/dev` is on its own device (devfs) on macOS and a devtmpfs on Linux, both unlike `/`.
    let r = srv.exec(&at("readdir", "dev"));
    assert!(matches!(&r, Err(e) if e.errno == "EXDEV"), "{r:?}");
    let listing = srv.exec(&at("readdir", "")).unwrap();
    assert!(!listing
        .entries
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["name"] == "dev"));
}

// ── invisible things ──────────────────────────────────────────────

#[test]
fn sockets_fifos_and_non_utf8_names_do_not_exist_for_the_host() {
    let f = fx(true);
    std::fs::write(f.root.join("plain"), b"p").unwrap();
    let _listener = std::os::unix::net::UnixListener::bind(f.root.join("sock")).unwrap();
    let fifo = CString::new(f.root.join("fifo").to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    use std::os::unix::ffi::OsStrExt;
    let odd = f.root.join(std::ffi::OsStr::from_bytes(b"bad-\xff-name"));
    let odd_made = std::fs::write(&odd, b"x").is_ok(); // APFS refuses these names
    assert_eq!(f.names(""), vec!["plain".to_string()]);
    assert!(odd_made || cfg!(target_os = "macos"));
    for name in ["sock", "fifo"] {
        assert_eq!(f.errno(at("stat", name)), "ENOENT", "{name}");
        assert_eq!(f.errno(open_req(name, &["read"])), "ENOENT", "{name}");
        assert_eq!(f.errno(open_req(name, &["write"])), "ENOENT", "{name}");
        assert_eq!(f.errno(at("unlink", name)), "ENOENT", "{name}");
        assert_eq!(
            f.errno(ShareRequestPayload {
                to: Some("x".into()),
                ..at("rename", name)
            }),
            "ENOENT"
        );
    }
    assert!(f.root.join("sock").exists() && f.root.join("fifo").exists());
}

#[test]
fn a_fifo_swapped_in_after_the_listing_cannot_hang_the_server() {
    let f = fx(false);
    let fifo = CString::new(f.root.join("pipe").to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let t = Instant::now();
    assert_eq!(f.errno(open_req("pipe", &["read"])), "ENOENT");
    assert!(t.elapsed() < Duration::from_secs(2));
}

// ── hard links ────────────────────────────────────────────────────

#[test]
fn a_hard_linked_file_is_not_writable_but_still_readable() {
    let f = fx(true);
    let target = f.outside.join("secret.txt");
    std::fs::hard_link(&target, f.root.join("hl")).unwrap();
    assert_eq!(f.cat("hl").unwrap(), b"TOP SECRET");
    assert_eq!(f.errno(open_req("hl", &["write"])), "EPERM");
    assert_eq!(f.errno(open_req("hl", &["write", "trunc"])), "EPERM");
    assert_eq!(f.errno(open_req("hl", &["read", "write"])), "EPERM");
    assert_eq!(
        f.errno(ShareRequestPayload {
            attr: json!({"size": 0}),
            ..at("setattr", "hl")
        }),
        "EPERM"
    );
    assert_eq!(
        f.errno(ShareRequestPayload {
            attr: json!({"mode": 0o777}),
            ..at("setattr", "hl")
        }),
        "EPERM"
    );
    assert_eq!(std::fs::read(&target).unwrap(), b"TOP SECRET");
    assert_eq!(
        std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        0o644
    );
    // Removing the NAME is harmless: it does not touch the other one.
    f.run(at("unlink", "hl")).unwrap();
    assert!(target.exists());
}

// ── the root ──────────────────────────────────────────────────────

#[test]
fn a_root_that_is_a_symlink_is_resolved_once_at_startup() {
    let tmp = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(tmp.path()).unwrap();
    let real = base.join("real");
    std::fs::create_dir(&real).unwrap();
    std::fs::write(real.join("f"), b"in").unwrap();
    let link = base.join("link");
    symlink(&real, &link).unwrap();
    let share = Share::open(&ShareSpec {
        name: "s".into(),
        path: link,
        writable: false,
    })
    .unwrap();
    assert_eq!(share.root_path, real, "the start-up line shows the real place");
    let srv = ShareServer::new(vec![share], limits());
    assert!(srv.exec(&at("stat", "f")).is_ok());
}

#[test]
fn a_root_replaced_while_running_is_noticed() {
    for how in ["new-directory", "symlink", "removed"] {
        let f = fx(true);
        std::fs::write(f.root.join("f"), b"old").unwrap();
        assert!(f.run(at("stat", "f")).is_ok());
        let held = f.run(open_req("f", &["read"])).unwrap().handle.unwrap();
        let moved = f.root.with_file_name("share-moved");
        std::fs::rename(&f.root, &moved).unwrap();
        match how {
            "new-directory" => {
                std::fs::create_dir(&f.root).unwrap();
                std::fs::write(f.root.join("f"), b"NEW").unwrap();
            }
            "symlink" => symlink(&f.outside, &f.root).unwrap(),
            _ => {}
        }
        assert_eq!(f.errno(at("stat", "f")), "ESTALE", "{how}");
        assert_eq!(f.errno(at("readdir", "")), "ESTALE", "{how}");
        assert_eq!(f.errno(open_req("f", &["read"])), "ESTALE", "{how}");
        // A handle opened before is not served either.
        assert_eq!(
            f.errno(ShareRequestPayload {
                handle: Some(held),
                offset: Some(0),
                length: Some(3),
                ..rq("read")
            }),
            "ESTALE",
            "{how}"
        );
    }
}

// ── read-only ─────────────────────────────────────────────────────

#[test]
fn a_read_only_share_refuses_every_change() {
    let f = fx(false);
    std::fs::write(f.root.join("f"), b"keep").unwrap();
    std::fs::create_dir(f.root.join("d")).unwrap();
    let to = |p: &str| ShareRequestPayload {
        to: Some("zz".into()),
        ..at("rename", p)
    };
    let setattr = |a: Value| ShareRequestPayload {
        attr: a,
        ..at("setattr", "f")
    };
    for (what, r) in [
        ("create", at("create", "new")),
        ("open write", open_req("f", &["write"])),
        ("open create", open_req("new", &["write", "create"])),
        ("open trunc", open_req("f", &["read", "trunc"])),
        ("mkdir", at("mkdir", "nd")),
        ("unlink", at("unlink", "f")),
        ("rmdir", at("rmdir", "d")),
        ("rename", to("f")),
        ("chmod", setattr(json!({"mode": 0o777}))),
        ("truncate", setattr(json!({"size": 0}))),
        ("times", setattr(json!({"mtime_ms": 1000}))),
    ] {
        assert_eq!(f.errno(r), "EROFS", "{what}");
    }
    assert_eq!(std::fs::read(f.root.join("f")).unwrap(), b"keep");
    assert!(f.root.join("d").exists() && !f.root.join("new").exists());
    // A read-only handle cannot be written even if the host tries.
    let h = f.run(open_req("f", &["read"])).unwrap().handle.unwrap();
    assert_eq!(
        f.errno(ShareRequestPayload {
            handle: Some(h),
            offset: Some(0),
            data: Some(b"x".to_vec()),
            ..rq("write")
        }),
        "EBADF"
    );
}

// ── writing ───────────────────────────────────────────────────────

#[test]
fn a_writable_share_creates_writes_renames_and_removes() {
    let f = fx(true);
    let c = f
        .run(ShareRequestPayload {
            mode: Some(0o7777),
            ..at("create", "new.txt")
        })
        .unwrap();
    let h = c.handle.unwrap();
    for (off, chunk) in [(0u64, "hello "), (6, "world")] {
        let w = f
            .run(ShareRequestPayload {
                handle: Some(h),
                offset: Some(off),
                data: Some(chunk.as_bytes().to_vec()),
                ..rq("write")
            })
            .unwrap();
        assert_eq!(w.written, Some(chunk.len() as u32));
    }
    f.run(ShareRequestPayload {
        handle: Some(h),
        ..rq("close")
    })
    .unwrap();
    assert_eq!(std::fs::read(f.root.join("new.txt")).unwrap(), b"hello world");
    let mode = std::fs::metadata(f.root.join("new.txt"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(
        mode & 0o7022,
        0,
        "a created file is never setuid or group/other-writable (mode {mode:o})"
    );
    assert_eq!(f.errno(at("create", "new.txt")), "EEXIST");
    f.run(at("mkdir", "sub")).unwrap();
    let dmode = std::fs::metadata(f.root.join("sub")).unwrap().permissions().mode();
    assert_eq!(dmode & 0o7022, 0);
    f.run(ShareRequestPayload {
        to: Some("sub/moved.txt".into()),
        ..at("rename", "new.txt")
    })
    .unwrap();
    assert_eq!(f.errno(at("rmdir", "sub")), "ENOTEMPTY");
    assert_eq!(f.errno(at("unlink", "sub")), "EISDIR");
    f.run(at("unlink", "sub/moved.txt")).unwrap();
    f.run(at("rmdir", "sub")).unwrap();
    assert_eq!(f.errno(at("rmdir", "")), "EBUSY", "the root stays");
    assert_eq!(f.errno(at("unlink", "")), "EBUSY");
    // open-or-create, truncate.
    let h = f
        .run(open_req("oc", &["write", "create"]))
        .unwrap()
        .handle
        .unwrap();
    f.run(ShareRequestPayload {
        handle: Some(h),
        offset: Some(0),
        data: Some(b"12345".to_vec()),
        ..rq("write")
    })
    .unwrap();
    f.run(ShareRequestPayload {
        handle: Some(h),
        ..rq("close")
    })
    .unwrap();
    let h = f
        .run(open_req("oc", &["write", "trunc"]))
        .unwrap()
        .handle
        .unwrap();
    f.run(ShareRequestPayload {
        handle: Some(h),
        ..rq("close")
    })
    .unwrap();
    assert_eq!(std::fs::read(f.root.join("oc")).unwrap(), b"");
    assert_eq!(f.errno(open_req("oc", &["write", "create", "excl"])), "EEXIST");
}

#[test]
fn setattr_changes_permission_bits_times_and_size_only() {
    let f = fx(true);
    std::fs::write(f.root.join("f"), b"0123456789").unwrap();
    let r = f
        .run(ShareRequestPayload {
            attr: json!({"mode": 0o4755, "mtime_ms": 1_000_000_000_000.0_f64, "size": 4}),
            ..at("setattr", "f")
        })
        .unwrap();
    assert_eq!(r.attr["size"], 4);
    let m = std::fs::metadata(f.root.join("f")).unwrap();
    assert_eq!(m.permissions().mode() & 0o7777, 0o755, "no setuid bit");
    assert_eq!(m.mtime(), 1_000_000_000);
    assert_eq!(std::fs::read(f.root.join("f")).unwrap(), b"0123");
    // On a directory: mode and times work, size does not.
    std::fs::create_dir(f.root.join("d")).unwrap();
    assert!(f
        .run(ShareRequestPayload {
            attr: json!({"mode": 0o700}),
            ..at("setattr", "d")
        })
        .is_ok());
    assert_eq!(
        f.errno(ShareRequestPayload {
            attr: json!({"size": 0}),
            ..at("setattr", "d")
        }),
        "EISDIR"
    );
}

// ── bounds ────────────────────────────────────────────────────────

#[test]
fn open_handles_are_bounded_and_closing_frees_one() {
    let f = fx(false);
    std::fs::write(f.root.join("f"), b"x").unwrap();
    let mut hs = Vec::new();
    for _ in 0..4 {
        hs.push(f.run(open_req("f", &["read"])).unwrap().handle.unwrap());
    }
    assert_eq!(f.errno(open_req("f", &["read"])), "EMFILE");
    assert_eq!(f.srv.open_handles(), 4);
    f.run(ShareRequestPayload {
        handle: Some(hs[0]),
        ..rq("close")
    })
    .unwrap();
    assert!(f.run(open_req("f", &["read"])).is_ok());
    assert_eq!(f.errno(ShareRequestPayload { handle: Some(hs[0]), ..rq("close") }), "EBADF");
    f.srv.shutdown();
    assert_eq!(f.srv.open_handles(), 0, "connection end drops every handle");
}

#[test]
fn bytes_per_operation_are_bounded() {
    let f = fx(true);
    std::fs::write(f.root.join("big"), vec![1u8; 100_000]).unwrap();
    let h = f.run(open_req("big", &["read", "write"])).unwrap().handle.unwrap();
    let r = f
        .run(ShareRequestPayload {
            handle: Some(h),
            offset: Some(0),
            length: Some(u32::MAX),
            ..rq("read")
        })
        .unwrap();
    assert_eq!(r.data.unwrap().len(), 4096, "a read is clamped to max_bytes");
    assert_eq!(
        f.errno(ShareRequestPayload {
            handle: Some(h),
            offset: Some(0),
            data: Some(vec![0; 4097]),
            ..rq("write")
        }),
        "EINVAL"
    );
    assert_eq!(
        f.errno(ShareRequestPayload {
            handle: Some(h),
            offset: Some(1 << 41),
            data: Some(vec![0; 10]),
            ..rq("write")
        }),
        "EFBIG"
    );
}

#[test]
fn directory_size_and_page_size_are_bounded() {
    let f = fx(false);
    for i in 0..51 {
        std::fs::write(f.root.join(format!("f{i:03}")), b"").unwrap();
    }
    assert_eq!(f.errno(at("readdir", "")), "EFBIG");
    let g = fx(false);
    for i in 0..20 {
        std::fs::write(g.root.join(format!("f{i:03}")), b"").unwrap();
    }
    let r = g
        .run(ShareRequestPayload {
            length: Some(u32::MAX),
            ..at("readdir", "")
        })
        .unwrap();
    assert_eq!(r.entries.as_array().unwrap().len(), 5, "page_entries caps what was asked");
}

#[test]
fn paths_are_bounded() {
    let f = fx(false);
    assert_eq!(f.errno(at("stat", &"a/".repeat(2500))), "ENAMETOOLONG");
    assert_eq!(f.errno(at("stat", &"x".repeat(256))), "ENAMETOOLONG");
    assert_eq!(f.errno(at("stat", &"a/".repeat(129))), "ENAMETOOLONG");
    assert_eq!(f.errno(at("stat", &"a/".repeat(100))), "ENOENT", "within bounds: just absent");
}

#[test]
fn an_unknown_share_op_or_handle_is_refused() {
    let f = fx(true);
    assert_eq!(f.errno(ShareRequestPayload { share: "other".into(), ..at("stat", "") }), "EACCES");
    assert_eq!(f.errno(rq("frobnicate")), "ENOTSUP");
    assert_eq!(f.errno(ShareRequestPayload { handle: Some(99), offset: Some(0), length: Some(1), ..rq("read") }), "EBADF");
    assert_eq!(f.errno(open_req("", &["read"])), "EISDIR");
    assert_eq!(f.errno(open_req("x", &["bogus"])), "EINVAL");
    assert_eq!(f.errno(open_req("x", &[])), "EINVAL");
}

#[tokio::test]
async fn the_total_rate_is_bounded() {
    let f = fx_with(
        false,
        Limits {
            bytes_per_sec: 64 * 1024,
            burst_bytes: 8 * 1024,
            max_bytes: 16 * 1024,
            ..limits()
        },
    );
    std::fs::write(f.root.join("f"), vec![5u8; 96 * 1024]).unwrap();
    let h = f.run(open_req("f", &["read"])).unwrap().handle.unwrap();
    let t = Instant::now();
    for i in 0..6u64 {
        let rep = f
            .srv
            .serve(ShareRequestPayload {
                handle: Some(h),
                offset: Some(i * 16 * 1024),
                length: Some(16 * 1024),
                ..rq("read")
            })
            .await;
        assert!(rep.ok);
    }
    // 96 KiB at 64 KiB/s after an 8 KiB burst: about 1.4 s. Allow slack, but it cannot be instant.
    assert!(
        t.elapsed() >= Duration::from_millis(1000),
        "the rate limit did not hold: {:?}",
        t.elapsed()
    );
}

#[tokio::test]
async fn serve_turns_errors_into_error_replies_with_the_request_id() {
    let f = fx(false);
    let rep = f
        .srv
        .serve(ShareRequestPayload {
            request_id: 77,
            ..at("stat", "../x")
        })
        .await;
    assert_eq!(rep.request_id, 77);
    assert!(!rep.ok);
    assert_eq!(rep.errno.as_deref(), Some("EINVAL"));
}
