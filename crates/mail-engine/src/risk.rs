use rinse_mail::AttachmentRisk;

fn severity(risk: AttachmentRisk) -> u8 {
    match risk {
        AttachmentRisk::Executable => 9,
        AttachmentRisk::Script => 8,
        AttachmentRisk::MacroDocument => 7,
        AttachmentRisk::DiskImage => 6,
        AttachmentRisk::Archive => 5,
        AttachmentRisk::Document => 4,
        AttachmentRisk::Calendar => 3,
        AttachmentRisk::Contact => 3,
        AttachmentRisk::Image => 2,
        AttachmentRisk::Other => 0,
    }
}

/// The lowercase extension as Windows would see it: an NTFS stream suffix (`:$DATA`, `::$DATA`)
/// and trailing dots and spaces are ignored.
fn extension(name: &str) -> String {
    let mut name = name;
    if let Some(i) = name.find(':') {
        name = &name[..i];
    }
    let name = name.trim_end_matches(|c: char| c == '.' || c.is_whitespace());
    name.rsplit_once('.')
        .map(|(_, e)| e.trim().to_ascii_lowercase())
        .unwrap_or_default()
}

/// Office, OpenDocument, iWork and EPUB formats that are zip containers by design.
fn zip_document(ext: &str) -> bool {
    matches!(
        ext,
        "docx"
            | "xlsx"
            | "pptx"
            | "dotx"
            | "xltx"
            | "potx"
            | "ppsx"
            | "odt"
            | "ods"
            | "odp"
            | "odg"
            | "pages"
            | "numbers"
            | "key"
            | "epub"
    )
}

fn by_extension(name: &str) -> AttachmentRisk {
    match extension(name).as_str() {
        "exe" | "com" | "scr" | "msi" | "msp" | "msix" | "appx" | "dll" | "cpl" | "pif" | "app"
        | "apk" | "aab" | "ipa" | "deb" | "rpm" | "pkg" | "mpkg" | "appimage" | "lnk" | "jar"
        | "elf" | "bin" | "run" | "gadget" | "inf" | "reg" | "xpi" | "crx" | "sys" | "drv"
        | "msc" | "jnlp" | "appref-ms" | "diagcab" | "terminal" => AttachmentRisk::Executable,
        "js" | "jse" | "mjs" | "vbs" | "vbe" | "wsf" | "wsh" | "wsc" | "ps1" | "psm1" | "psd1"
        | "bat" | "cmd" | "sh" | "bash" | "zsh" | "csh" | "command" | "py" | "pyw" | "rb"
        | "pl" | "php" | "hta" | "html" | "htm" | "xhtml" | "shtml" | "mht" | "mhtml" | "svg"
        | "svgz" | "applescript" | "scpt" | "workflow" | "url" | "website"
        | "settingcontent-ms" | "library-ms" | "chm" | "xll" | "xsl" | "one" | "scf"
        | "search-ms" | "searchconnector-ms" | "iqy" | "slk" | "fileloc" | "webloc" | "inetloc" => {
            AttachmentRisk::Script
        }
        "docm" | "dotm" | "xlsm" | "xltm" | "xlam" | "xlsb" | "pptm" | "potm" | "ppam" | "ppsm"
        | "sldm" | "doc" | "dot" | "xls" | "xlt" | "ppt" | "pps" | "pot" | "rtf" | "pub" => {
            AttachmentRisk::MacroDocument
        }
        "iso" | "img" | "dmg" | "vhd" | "vhdx" | "vmdk" | "udf" | "sparseimage" | "toast" => {
            AttachmentRisk::DiskImage
        }
        "zip" | "rar" | "7z" | "tar" | "gz" | "tgz" | "bz2" | "tbz" | "xz" | "txz" | "zst"
        | "cab" | "arj" | "lzh" | "lha" | "ace" | "z" | "cpio" | "xar" => AttachmentRisk::Archive,
        "pdf" | "docx" | "dotx" | "xlsx" | "xltx" | "pptx" | "potx" | "ppsx" | "odt" | "ods"
        | "odp" | "odg" | "txt" | "csv" | "md" | "pages" | "numbers" | "key" | "epub" | "xml"
        | "json" => AttachmentRisk::Document,
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "bmp" | "heic" | "heif" | "avif" | "tif"
        | "tiff" | "ico" => AttachmentRisk::Image,
        "ics" | "ical" | "ifb" | "vcs" => AttachmentRisk::Calendar,
        "vcf" | "vcard" => AttachmentRisk::Contact,
        _ => AttachmentRisk::Other,
    }
}

fn by_type(media: &str) -> AttachmentRisk {
    match media {
        "application/x-msdownload"
        | "application/x-msdos-program"
        | "application/x-ms-installer"
        | "application/x-msi"
        | "application/vnd.microsoft.portable-executable"
        | "application/x-executable"
        | "application/x-mach-binary"
        | "application/x-elf"
        | "application/java-archive"
        | "application/vnd.android.package-archive"
        | "application/x-apple-diskimage-installer" => AttachmentRisk::Executable,
        "application/javascript"
        | "text/javascript"
        | "application/x-javascript"
        | "text/vbscript"
        | "application/x-sh"
        | "application/x-shellscript"
        | "text/x-shellscript"
        | "application/x-bat"
        | "application/hta"
        | "text/html"
        | "application/xhtml+xml"
        | "image/svg+xml"
        | "message/rfc822-html"
        | "application/x-python-code" => AttachmentRisk::Script,
        "application/msword"
        | "application/vnd.ms-excel"
        | "application/vnd.ms-powerpoint"
        | "application/rtf"
        | "text/rtf" => AttachmentRisk::MacroDocument,
        m if m.contains("macroenabled") => AttachmentRisk::MacroDocument,
        "application/x-iso9660-image"
        | "application/x-apple-diskimage"
        | "application/x-raw-disk-image" => AttachmentRisk::DiskImage,
        "application/zip"
        | "application/x-zip-compressed"
        | "application/x-rar-compressed"
        | "application/vnd.rar"
        | "application/x-7z-compressed"
        | "application/gzip"
        | "application/x-gzip"
        | "application/x-tar"
        | "application/x-bzip2"
        | "application/x-xz"
        | "application/vnd.ms-cab-compressed"
        | "application/zstd" => AttachmentRisk::Archive,
        "text/calendar" | "application/ics" => AttachmentRisk::Calendar,
        "text/vcard" | "text/x-vcard" | "text/directory" => AttachmentRisk::Contact,
        "application/pdf" | "text/plain" | "text/csv" => AttachmentRisk::Document,
        m if m.starts_with("application/vnd.openxmlformats-officedocument")
            || m.starts_with("application/vnd.oasis.opendocument") =>
        {
            AttachmentRisk::Document
        }
        m if m.starts_with("image/") => AttachmentRisk::Image,
        _ => AttachmentRisk::Other,
    }
}

/// The media type and class recognized from the first bytes of the content.
pub(crate) fn sniff(head: &[u8]) -> Option<(&'static str, AttachmentRisk)> {
    let starts = |m: &[u8]| head.starts_with(m);
    let trimmed: &[u8] = {
        let skip = head
            .iter()
            .position(|b| !b.is_ascii_whitespace())
            .unwrap_or(head.len());
        let rest = &head[skip..];
        rest.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(rest)
    };
    let text_starts =
        |m: &[u8]| trimmed.len() >= m.len() && trimmed[..m.len()].eq_ignore_ascii_case(m);
    Some(if starts(b"MZ") {
        (
            "application/vnd.microsoft.portable-executable",
            AttachmentRisk::Executable,
        )
    } else if starts(b"\x7FELF") {
        ("application/x-elf", AttachmentRisk::Executable)
    } else if starts(&[0xFE, 0xED, 0xFA, 0xCE])
        || starts(&[0xFE, 0xED, 0xFA, 0xCF])
        || starts(&[0xCE, 0xFA, 0xED, 0xFE])
        || starts(&[0xCF, 0xFA, 0xED, 0xFE])
        || starts(&[0xCA, 0xFE, 0xBA, 0xBE])
    {
        ("application/x-mach-binary", AttachmentRisk::Executable)
    } else if starts(b"#!") {
        ("text/x-shellscript", AttachmentRisk::Script)
    } else if text_starts(b"<!doctype html") || text_starts(b"<html") || text_starts(b"<script") {
        ("text/html", AttachmentRisk::Script)
    } else if text_starts(b"<svg")
        || (text_starts(b"<?xml") && head.windows(4).any(|w| w == b"<svg"))
    {
        ("image/svg+xml", AttachmentRisk::Script)
    } else if starts(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
        ("application/x-ole-storage", AttachmentRisk::MacroDocument)
    } else if starts(b"{\\rtf") {
        ("application/rtf", AttachmentRisk::MacroDocument)
    } else if starts(b"%PDF-") {
        ("application/pdf", AttachmentRisk::Document)
    } else if starts(b"PK\x03\x04") || starts(b"PK\x05\x06") {
        ("application/zip", AttachmentRisk::Archive)
    } else if starts(b"Rar!\x1A\x07") {
        ("application/vnd.rar", AttachmentRisk::Archive)
    } else if starts(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
        ("application/x-7z-compressed", AttachmentRisk::Archive)
    } else if starts(&[0x1F, 0x8B]) {
        ("application/gzip", AttachmentRisk::Archive)
    } else if starts(b"BZh") {
        ("application/x-bzip2", AttachmentRisk::Archive)
    } else if starts(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]) {
        ("application/x-xz", AttachmentRisk::Archive)
    } else if starts(b"MSCF") {
        ("application/vnd.ms-cab-compressed", AttachmentRisk::Archive)
    } else if head.len() > 0x8005 && &head[0x8001..0x8006] == b"CD001" {
        ("application/x-iso9660-image", AttachmentRisk::DiskImage)
    } else if starts(b"\x89PNG\r\n\x1a\n") {
        ("image/png", AttachmentRisk::Image)
    } else if starts(&[0xFF, 0xD8, 0xFF]) {
        ("image/jpeg", AttachmentRisk::Image)
    } else if starts(b"GIF87a") || starts(b"GIF89a") {
        ("image/gif", AttachmentRisk::Image)
    } else if starts(b"RIFF") && head.get(8..12) == Some(b"WEBP") {
        ("image/webp", AttachmentRisk::Image)
    } else if text_starts(b"BEGIN:VCALENDAR") {
        ("text/calendar", AttachmentRisk::Calendar)
    } else if text_starts(b"BEGIN:VCARD") {
        ("text/vcard", AttachmentRisk::Contact)
    } else {
        return None;
    })
}

/// The most dangerous class among the file name's extension, the declared type and the
/// sniffed content. A zip is not counted as an archive only under a zip-based document
/// extension (OOXML, OpenDocument, iWork, EPUB); macro-capable OOXML is caught by its extension.
pub(crate) fn classify(
    file_name: Option<&str>,
    declared: &str,
    sniffed: Option<AttachmentRisk>,
) -> AttachmentRisk {
    let mut risks = vec![by_type(declared)];
    if let Some(name) = file_name {
        risks.push(by_extension(name));
    }
    if let Some(s) = sniffed {
        let office_zip =
            s == AttachmentRisk::Archive && file_name.is_some_and(|n| zip_document(&extension(n)));
        if !office_zip {
            risks.push(s);
        }
    }
    risks
        .into_iter()
        .max_by_key(|r| severity(*r))
        .unwrap_or(AttachmentRisk::Other)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes() {
        assert_eq!(
            classify(Some("a.pdf"), "application/pdf", None),
            AttachmentRisk::Document
        );
        assert_eq!(
            classify(
                Some("invoice.pdf"),
                "application/pdf",
                sniff(b"MZ\x90").map(|s| s.1)
            ),
            AttachmentRisk::Executable
        );
        assert_eq!(
            classify(Some("x.docm"), "application/octet-stream", None),
            AttachmentRisk::MacroDocument
        );
        assert_eq!(
            classify(
                Some("x.docx"),
                "application/octet-stream",
                sniff(b"PK\x03\x04").map(|s| s.1)
            ),
            AttachmentRisk::Document
        );
        assert_eq!(
            classify(None, "application/zip", None),
            AttachmentRisk::Archive
        );
        assert_eq!(
            classify(Some("i.ics"), "text/calendar", None),
            AttachmentRisk::Calendar
        );
        assert_eq!(
            classify(Some("p.HTML"), "text/plain", None),
            AttachmentRisk::Script
        );
        assert_eq!(
            classify(Some("d.iso"), "application/octet-stream", None),
            AttachmentRisk::DiskImage
        );
        assert_eq!(
            classify(None, "application/octet-stream", None),
            AttachmentRisk::Other
        );
        assert_eq!(
            sniff(b"  BEGIN:VCARD\r\n").unwrap().1,
            AttachmentRisk::Contact
        );
    }

    #[test]
    fn zip_behind_a_plain_document_extension_is_an_archive() {
        let zip = sniff(b"PK\x03\x04").map(|s| s.1);
        for name in ["invoice.pdf", "a.txt", "a.csv", "a.json", "a.md", "a.xml"] {
            assert_eq!(
                classify(Some(name), "application/pdf", zip),
                AttachmentRisk::Archive,
                "{name}"
            );
        }
        for name in ["a.xlsx", "a.odt", "a.pages", "a.epub"] {
            assert_eq!(
                classify(Some(name), "application/octet-stream", zip),
                AttachmentRisk::Document,
                "{name}"
            );
        }
    }

    #[test]
    fn windows_name_tricks() {
        for name in [
            "evil.exe.",
            "evil.hta. ",
            "evil.exe . .",
            "evil.exe::$DATA",
            "evil.exe:x",
        ] {
            assert_ne!(
                classify(Some(name), "text/plain", None),
                AttachmentRisk::Document,
                "{name}"
            );
            assert!(
                matches!(
                    by_extension(name),
                    AttachmentRisk::Executable | AttachmentRisk::Script
                ),
                "{name}"
            );
        }
    }

    #[test]
    fn more_dangerous_types() {
        for ext in ["msc", "jnlp", "appref-ms", "diagcab", "terminal"] {
            assert_eq!(
                by_extension(&format!("a.{ext}")),
                AttachmentRisk::Executable,
                "{ext}"
            );
        }
        for ext in [
            "scf",
            "search-ms",
            "iqy",
            "slk",
            "fileloc",
            "webloc",
            "inetloc",
        ] {
            assert_eq!(
                by_extension(&format!("a.{ext}")),
                AttachmentRisk::Script,
                "{ext}"
            );
        }
    }
}
