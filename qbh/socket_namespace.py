"""Linux privileged network boundary for direct socket assessment workers.

The network namespace is owned by the host user namespace. Scanner processes
enter a separate unprivileged user namespace and cannot alter its firewall.
HTTP path/method policies require HTTP mediation, not just this L3/L4 boundary.
"""

from __future__ import annotations

import ipaddress
import json
import secrets
import shutil
import subprocess
import tempfile
from pathlib import Path

from .authorization import RuleForbidden
from .network_policy import validate_ip


class SocketNamespace:
    def __init__(self, authorization, destinations, *, ports, bindings=None):
        authorization.ensure_active()
        if authorization.dry_run:
            raise RuleForbidden("dry_run_process_forbidden")
        if authorization.request_restrictions:
            raise RuleForbidden("raw_socket_path_policy_requires_application_gateway")
        self.auth = authorization
        self.destinations = tuple(str(ipaddress.ip_address(ip)) for ip in destinations)
        if not self.destinations or len(self.destinations) > 256:
            raise RuleForbidden("invalid_socket_destination_count")
        self.bindings = {
            str(ipaddress.ip_address(ip)): tuple(names)
            for ip, names in (bindings or {}).items()
        }
        self.destination_ports = {
            ip: tuple(sorted(set(ports[ip] if isinstance(ports, dict) else ports)))
            for ip in self.destinations
        }
        self.port_ranges = {}
        for ip, values in self.destination_ports.items():
            if not values or any(
                type(p) is not int or not 1 <= p <= 65535 for p in values
            ):
                raise RuleForbidden("invalid_socket_ports")
            groups = []
            start = end = values[0]
            for port in values[1:]:
                if port == end + 1:
                    end = port
                else:
                    groups.append(str(start) if start == end else f"{start}:{end}")
                    start = end = port
            groups.append(str(start) if start == end else f"{start}:{end}")
            self.port_ranges[ip] = groups
        if sum(map(len, self.port_ranges.values())) > 1024:
            raise RuleForbidden("socket_firewall_rule_budget_exceeded")
        self.validate()
        self.hosts_file = None
        self.binary_files = []
        suffix = secrets.token_hex(4)
        self.name = "xez-" + suffix
        self.host_if, self.child_if = "xh" + suffix, "xc" + suffix
        number = secrets.randbelow(16384)
        network = ipaddress.ip_network(f"198.19.{number // 64}.{(number % 64) * 4}/30")
        self.gateway, self.address = str(network[1]), str(network[2])
        self.gateway6 = f"fd42:{suffix[:4]}:{suffix[4:]}::1"
        self.address6 = f"fd42:{suffix[:4]}:{suffix[4:]}::2"
        self.created = self.linked = False
        self.host_rules = []

    @staticmethod
    def command(*args):
        return subprocess.run(
            ["sudo", "-n", *args], check=True, capture_output=True, timeout=15
        )

    def inside(self, *args):
        return self.command("ip", "netns", "exec", self.name, *args)

    def host_rule(self, table, chain, *rule, family="iptables"):
        self.command(family, "-w", "-t", table, "-I", chain, "1", *rule)
        self.host_rules.append((family, table, chain, rule))

    def validate(self):
        self.auth.ensure_active()
        if self.auth.dry_run or self.auth.request_restrictions:
            raise RuleForbidden("raw_socket_policy_changed")
        for ip in self.destinations:
            names = self.bindings.get(ip, ())
            if names:
                for name in names:
                    self.auth.authorize_host(name)
            else:
                self.auth.authorize_host(ip)
            validate_ip(self.auth, ip)

    def __enter__(self):
        self.validate()
        try:
            self.command("ip", "netns", "add", self.name)
            self.created = True
            self.command(
                "ip",
                "link",
                "add",
                self.host_if,
                "type",
                "veth",
                "peer",
                "name",
                self.child_if,
            )
            self.linked = True
            self.command("ip", "link", "set", self.child_if, "netns", self.name)
            self.command("ip", "addr", "add", self.gateway + "/30", "dev", self.host_if)
            self.command("ip", "link", "set", self.host_if, "up")
            self.inside("ip", "addr", "add", self.address + "/30", "dev", self.child_if)
            self.inside("ip", "link", "set", self.child_if, "up")
            self.inside("ip", "link", "set", "lo", "up")
            ipv6 = any(":" in ip for ip in self.destinations)
            if ipv6:
                self.command(
                    "ip",
                    "-6",
                    "addr",
                    "add",
                    self.gateway6 + "/64",
                    "dev",
                    self.host_if,
                    "nodad",
                )
                self.inside(
                    "ip",
                    "-6",
                    "addr",
                    "add",
                    self.address6 + "/64",
                    "dev",
                    self.child_if,
                    "nodad",
                )
            # Default deny precedes any scanner process, for both address families.
            for family in ("iptables", "ip6tables"):
                self.inside(family, "-P", "OUTPUT", "DROP")
                self.inside(family, "-P", "FORWARD", "DROP")
                self.inside(family, "-P", "INPUT", "DROP")
                self.inside(
                    family,
                    "-A",
                    "INPUT",
                    "-m",
                    "conntrack",
                    "--ctstate",
                    "ESTABLISHED,RELATED",
                    "-j",
                    "ACCEPT",
                )
            if ipv6:
                # Permanent neighbors remove the need to grant the scanner any
                # ICMPv6 egress. MACs belong solely to our freshly created veth.
                host_mac = json.loads(
                    self.command("ip", "-j", "link", "show", self.host_if).stdout
                )[0]["address"]
                child_mac = json.loads(
                    self.inside("ip", "-j", "link", "show", self.child_if).stdout
                )[0]["address"]
                self.inside(
                    "ip",
                    "-6",
                    "neigh",
                    "replace",
                    self.gateway6,
                    "lladdr",
                    host_mac,
                    "nud",
                    "permanent",
                    "dev",
                    self.child_if,
                )
                self.command(
                    "ip",
                    "-6",
                    "neigh",
                    "replace",
                    self.address6,
                    "lladdr",
                    child_mac,
                    "nud",
                    "permanent",
                    "dev",
                    self.host_if,
                )
            for ip in self.destinations:
                six = ":" in ip
                family = "ip6tables" if six else "iptables"
                self.inside(
                    "ip",
                    "-6" if six else "-4",
                    "route",
                    "replace",
                    ip + ("/128" if six else "/32"),
                    "via",
                    self.gateway6 if six else self.gateway,
                )
                for port in self.port_ranges[ip]:
                    for protocol in ("tcp", "udp"):
                        self.inside(
                            family,
                            "-A",
                            "OUTPUT",
                            "-d",
                            ip,
                            "-p",
                            protocol,
                            "--dport",
                            str(port),
                            "-j",
                            "ACCEPT",
                        )
            for family, address in [("iptables", self.address)] + (
                [("ip6tables", self.address6)] if ipv6 else []
            ):
                self.inside(
                    family,
                    "-A",
                    "OUTPUT",
                    "-p",
                    "tcp",
                    "-j",
                    "REJECT",
                    "--reject-with",
                    "tcp-reset",
                )
                # These rules apply only to this task's unique veth.
                self.host_rule(
                    "filter", "FORWARD", "-i", self.host_if, "-j", "DROP", family=family
                )
                self.host_rule(
                    "filter",
                    "FORWARD",
                    "-i",
                    self.host_if,
                    "-s",
                    address,
                    "-j",
                    "ACCEPT",
                    family=family,
                )
                self.host_rule(
                    "filter",
                    "FORWARD",
                    "-o",
                    self.host_if,
                    "-m",
                    "conntrack",
                    "--ctstate",
                    "ESTABLISHED,RELATED",
                    "-j",
                    "ACCEPT",
                    family=family,
                )
                self.host_rule(
                    "nat",
                    "POSTROUTING",
                    "-s",
                    address,
                    "-j",
                    "MASQUERADE",
                    family=family,
                )
            hosts = ["127.0.0.1 localhost", "::1 localhost"]
            hosts.extend(
                f"{ip} {name}" for ip, names in self.bindings.items() for name in names
            )
            self.hosts_file = tempfile.NamedTemporaryFile(
                mode="w", prefix="xezer-hosts-", delete=False
            )
            self.hosts_file.write("\n".join(hosts) + "\n")
            self.hosts_file.close()
            Path(self.hosts_file.name).chmod(0o644)
            return self
        except BaseException:
            self.close()
            raise

    def wrap(self, command, *, timeout=None):
        self.validate()
        # Host root privileges end at bubblewrap; the executable runs without
        # capabilities in a new user/PID/filesystem namespace. No host proc/home.
        args = [
            "sudo",
            "-n",
            "ip",
            "netns",
            "exec",
            self.name,
            "bwrap",
            "--unshare-all",
            "--share-net",
            "--uid",
            "65534",
            "--gid",
            "65534",
            "--cap-drop",
            "ALL",
            "--die-with-parent",
            "--new-session",
            "--clearenv",
            "--ro-bind",
            "/usr",
            "/usr",
            "--symlink",
            "usr/bin",
            "/bin",
            "--symlink",
            "usr/lib",
            "/lib",
            "--symlink",
            "usr/lib64",
            "/lib64",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--dir",
            "/etc",
            "--ro-bind",
            "/etc/alternatives",
            "/etc/alternatives",
            "--ro-bind",
            "/etc/ld.so.cache",
            "/etc/ld.so.cache",
            "--setenv",
            "PATH",
            "/usr/bin:/bin",
            "--setenv",
            "HOME",
            "/tmp",
            "--chdir",
            "/tmp",
        ]
        if self.hosts_file:
            args += ["--ro-bind", self.hosts_file.name, "/etc/hosts"]
        executable = Path(command[0]).resolve()
        if not str(executable).startswith("/usr/"):
            fd = tempfile.NamedTemporaryFile(prefix="xezer-scanner-", delete=False)
            fd.close()
            self.binary_files.append(fd.name)
            shutil.copyfile(executable, fd.name)
            Path(fd.name).chmod(0o555)
            args += ["--ro-bind", fd.name, "/scanner"]
            command = ["/scanner", *command[1:]]
        if timeout is not None:
            command = ["/usr/bin/timeout", "-s", "KILL", str(timeout), *command]
        return args + ["--", *command]

    def terminate(self):
        if not self.created:
            return
        pids = self.command("ip", "netns", "pids", self.name).stdout.decode().split()
        if pids:
            self.command("kill", "-KILL", "--", *pids)

    def close(self):
        errors = []
        if self.created:
            try:
                self.terminate()
            except (OSError, subprocess.SubprocessError) as exc:
                errors.append(exc)
        for filename in self.binary_files:
            Path(filename).unlink(missing_ok=True)
        self.binary_files.clear()
        if self.hosts_file:
            Path(self.hosts_file.name).unlink(missing_ok=True)
            self.hosts_file = None
        for family, table, chain, rule in reversed(self.host_rules):
            try:
                self.command(family, "-w", "-t", table, "-D", chain, *rule)
            except (OSError, subprocess.SubprocessError) as exc:
                errors.append(exc)
        self.host_rules.clear()
        if self.linked:
            try:
                self.command("ip", "link", "del", self.host_if)
                self.linked = False
            except (OSError, subprocess.SubprocessError) as exc:
                errors.append(exc)
        if self.created:
            try:
                self.command("ip", "netns", "del", self.name)
                self.created = False
            except (OSError, subprocess.SubprocessError) as exc:
                errors.append(exc)
        if errors:
            raise RuntimeError(
                "socket_namespace_cleanup_failed; inspect task interface and rules"
            ) from errors[0]

    def __exit__(self, *exc):
        self.close()
