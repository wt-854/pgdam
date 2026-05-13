use pgdam_processor::enrichment::container::read_container_id;

#[cfg(test)]
mod tests {
    use super::*;

    fn extract(cgroup_content: &str) -> Option<String> {
        for line in cgroup_content.lines() {
            if let Some(rest) = line.split("cri-containerd-").nth(1) {
                if let Some(id) = rest.split('.').next() {
                    if id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit()) {
                        return Some(id.to_string());
                    }
                }
            }
            if let Some(rest) = line.split("docker-").nth(1) {
                if let Some(id) = rest.split('.').next() {
                    if id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit()) {
                        return Some(id.to_string());
                    }
                }
            }
            if let Some(id) = line
                .split('/')
                .find(|s| s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()))
            {
                return Some(id.to_string());
            }
        }
        None
    }

    const FAKE_ID: &str = "850e42c8a225a440e56c4499c2b9dda1db2693d1e48125c35536ec361f13c830";

    #[test]
    fn test_cgroup_v2_containerd() {
        let content = format!(
            "0::/../../kubepods-besteffort-pod83282ca4.slice/cri-containerd-{}.scope",
            FAKE_ID
        );
        assert_eq!(extract(&content), Some(FAKE_ID.to_string()));
    }

    #[test]
    fn test_cgroup_v2_docker() {
        let content = format!(
            "0::/../../kubepods-besteffort-pod83282ca4.slice/docker-{}.scope",
            FAKE_ID
        );
        assert_eq!(extract(&content), Some(FAKE_ID.to_string()));
    }

    #[test]
    fn test_cgroup_v1_docker() {
        let content = format!(
            "12:devices:/docker/{}\n11:memory:/docker/{}",
            FAKE_ID, FAKE_ID
        );
        assert_eq!(extract(&content), Some(FAKE_ID.to_string()));
    }

    #[test]
    fn test_no_container_id() {
        let content = "0::/init.scope\n0::/system.slice/sshd.service";
        assert_eq!(extract(content), None);
    }

    #[test]
    fn test_short_hex_not_matched() {
        // 12-char hex should not match as a container ID
        let content = "0::/docker/850e42c8a225";
        assert_eq!(extract(content), None);
    }

    #[test]
    fn test_non_hex_not_matched() {
        let content =
            "0::/kubepods/besteffort/podXXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX/not-a-container";
        assert_eq!(extract(content), None);
    }

    #[test]
    fn test_multiline_picks_first_match() {
        let content = format!(
            "0::/unrelated/path\n0::/kubepods/cri-containerd-{}.scope",
            FAKE_ID
        );
        assert_eq!(extract(&content), Some(FAKE_ID.to_string()));
    }
}
