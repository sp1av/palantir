def main(data):
    control = data["control"]
    read_til = data["read_til"]
    conn = data["conn"]
    output = {}
    capabilities_list = [
        "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER", "CAP_FSETID",
        "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_LINUX_IMMUTABLE",
        "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST", "CAP_NET_ADMIN", "CAP_NET_RAW",
        "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE", "CAP_SYS_PACCT",
        "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE", "CAP_SYS_RESOURCE", "CAP_SYS_TIME",
        "CAP_SYS_TTY_CONFIG", "CAP_MKNOD", "CAP_LEASE", "CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL",
        "CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN", "CAP_SYSLOG", "CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND",
        "CAP_AUDIT_READ", "CAP_PERFMON", "CAP_BPF", "CAP_CHECKPOINT_RESTORE"
    ]

    def parse_capabilities(cap_string):
        cap_int = int(cap_string, 16)
        cap_dict = {}
        for i, cap_name in enumerate(capabilities_list):
            cap_dict[cap_name] = bool(cap_int & (1 << i))
        return cap_dict

    def exec(data):
        return control(read_til, conn, data)
    control = data["control"]
    read_til = data["read_til"]
    conn = data["conn"]

    #DOCKER SOCKET

    if len(exec("cat /proc/self/mountinfo | grep docker.sock")) > 5:
        docker_socket_path = exec("grep docker.sock /proc/self/mountinfo | cut -d ' ' -f 5")
        docker_socket_path = docker_socket_path[docker_socket_path.find('/'):]
        if "docker.sock" in docker_socket_path:
            output["docker_socket"] = {
                "status": True,
                "details": docker_socket_path
            }

    # PRIVILEGED CHECK

    privileged_check = exec("grep 'CapEff' /proc/self/status | grep 'ffffffff'")
    if "ffffffff" in privileged_check.strip():
        output["privileged_mode"] = {
            "status": True,
            "details": "Container is running in privileged mode (has full root capabilities)."
        }

    # Docker group check

    group_check = exec("id -Gn | grep -w docker")
    if "docker" in group_check:
        output["docker_group"] = {
            "status": True,
            "details": "Container is part of the 'docker' group, meaning it can control other containers."
        }

    # Dangerous capabilities check
    output["bad_capabilities"] = {
        "status": False,
        "details": ""
    }
    bad_caps, find_bad_caps = ["cap_sys_admin", "cap_sys_ptrace", "cap_sys_module", "cap_dac_read_search", "cap_sys_rawio", "cap_mknod"], []
    caps = list(exec("grep CapEff /proc/self/status").split(":"))[1].strip()
    caps = parse_capabilities(caps)
    for i in bad_caps:
        if caps[i.upper()]:
            find_bad_caps.append(i)
    if len(find_bad_caps) > 0:
        output["bad_capabilities"] = {
            "status": True,
            "details": find_bad_caps
        }

    return output

