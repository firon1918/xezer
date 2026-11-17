<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:ccc146ff0bd6b343eca99f5f91ec19e66293b3142e31bb31187217eada58e15a -->

# Isolated vulnerability laboratory

## Juice Shop
`tests/labs/compose.yaml` pins Juice Shop v19.0.0 by image digest. It uses an internal Docker network, drops capabilities, sets resource limits, enables no-new-privileges and publishes only 127.0.0.1:3000. No credentials or persistent customer fixtures. Run `tests/labs/start.sh` on a working Linux Docker host; it waits for health. Run `tests/labs/stop.sh` to remove containers, network and volumes. Each start recreates synthetic application state. Never change the published host to 0.0.0.0.

Official project: https://owasp.org/www-project-juice-shop/ . Docker Compose configuration validation passed locally; image pull succeeded. Container execution failed with `cannot enter cgroupv2 ... with domain controllers -- it is in an invalid state`. Sandbox cgroup root is `domain threaded`; attempting a dedicated domain cgroup returned I/O error. No working application or successful detection is claimed. Containers/network were removed after the failed attempt. A normal Docker host with domain cgroups is required for this configuration.

For this sandbox the task-local Docker daemon used socket /tmp/xezer-docker.sock, data under $RUNTIME_ROOT/xezer-docker, and `DOCKER_HOST=unix:///tmp/xezer-docker.sock`. This socket configuration alone cannot overcome the cgroup limitation.

Use an explicit XEzer scope containing only 127.0.0.1 and point captured HAR at http://127.0.0.1:3000. Do not broaden scope to public domains. Until outbound subprocess enforcement is repaired, this lab setup does not establish unrestricted scanner safety.

## VulnHub workflow
Official image catalogue: https://www.vulnhub.com/ . No VM image has been downloaded or executed here. /dev/kvm and qemu-system-x86_64 were absent during initial inspection. Docker failure is a separate limitation; software-emulated VMs have not been evaluated.

On a dedicated virtualization host: choose one specific catalogue entry and record its download URL, version, size and publisher checksum. Download only that image; verify the published digest using sha256sum (a self-computed checksum alone does not authenticate the publisher). Extract archives with size limits. Inspect OVF/OVA appliance metadata before importing into VirtualBox, or inspect VMDK/QCOW2 with qemu-img info before a QEMU import. Treat imported appliance metadata as untrusted.

Create an internal or host-only network with no bridged adapter, NAT route or shared host folders. Attach scanner and target only to this network. Snapshot before each scenario, record exact guest address in XEzer scope, and restore after each test. Stop the guest and remove the host-only network when finished. These are provisioning instructions, not infrastructure validation. No VulnHub target is currently verified.

## Additional targets
WebGoat, crAPI and DVWA were not installed; prioritize them only after Juice Shop and the central transport boundary are verified.

## Verified namespace fallback

The historical Docker cgroup failure above remains specific to Compose in this sandbox. Juice Shop now runs with isolated Unix ingress using the same pinned image; see [mediation checkpoint](../audit/MEDIATION_PROGRESS.md) for exact startup, limitations and observed tests.


<!-- /coderabbit-ai-generated:v1 -->