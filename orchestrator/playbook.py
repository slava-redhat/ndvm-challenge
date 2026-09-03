"""Deterministic Ansible playbook generation for the recommended mitigation.

Trust rule (same as scoring.py / priority.py): the playbook is a Python-owned
artifact, NEVER LLM-guessed. Curated catalog options resolve to a real, tested
playbook template; anything else falls back to a valid scaffold of the option's
own documented steps. Every playbook is well-formed YAML and clearly marks the
vars David must fill before running (ports, service/namespace/workload names)
rather than inventing them.

Templates are authored as literal strings so Ansible's Jinja ({{ }}) survives
verbatim and no YAML serializer / dependency is needed. Parameters are injected
with __TOKEN__ replacement (no clash with {{ }} or shell $).
"""
import re


# The Red Hat Insights Remediations playbook disclaimer, verbatim, so NDVM's
# output reads like a real Insights playbook (envelope only — NDVM does not
# implement Insights' cryptographic playbook signing; see the footer).
_DISCLAIMER = (
    "# Red Hat Insights has recommended one or more actions for you, a system administrator, to review and if you\n"
    "# deem appropriate, deploy on your systems running Red Hat software. Based on the analysis, we have automatically\n"
    "# generated an Ansible Playbook for you. Please review and test the recommended actions and the Playbook as\n"
    "# they may contain configuration changes, updates, reboots and/or other changes to your systems. Red Hat is not\n"
    "# responsible for any adverse outcomes related to these recommendations or Playbooks."
)


def _scaffold_note(template_id):
    """The one extra trust notice a non-curated (scaffold) playbook needs: it is
    a documented-steps checklist, not tested module calls."""
    if template_id != "scaffold":
        return ""
    return ("# NOTE: documented-steps scaffold — each task records a manual step for review,\n"
            "#       not a tested module call. Turn steps into real tasks before automating.")


def _header(title, cve, fix_state, rhsa, product, version, sources, template_id):
    """Wrap the play in the Red Hat Insights Remediations playbook envelope
    (disclaimer + description/identifier header + NDVM footer), rendered in
    process. Ported from that service's format; NDVM is NOT signing it."""
    fixed = f" (fix: {rhsa})" if rhsa else ""
    # version is often already embedded in product ("...Linux 9") — don't repeat it
    parts = [product] + ([version] if version and version not in (product or "") else [])
    prod = " ".join(x for x in parts if x).strip() or "the affected host(s)"
    src = "\n".join(f"#   - {u}" for u in (sources or [])) or "#   - (none)"
    identifier = f"{cve},{template_id or 'mitigation'}" if cve else "unknown"
    note = _scaffold_note(template_id)
    manual = f"{note}\n" if note else ""
    return (
        "---\n"
        f"{_DISCLAIMER}\n"
        f"# {title or 'Mitigation'} for {cve or 'the reported CVE'}{fixed}\n"
        f"# Identifier: ({identifier})\n"
        f"# Version: {version or fix_state or 'unknown'}\n"
        f"# Product: {prod}   |   Red Hat fix_state: {fix_state or 'unknown'}\n"
        f"# Sources:\n{src}\n"
        f"#\n"
        f"{manual}"
        f"# Generated deterministically by NDVM — not model-authored. Rendered in the\n"
        f"# Red Hat Insights playbook format (adapted) — NOT cryptographically signed\n"
        f"# by Red Hat Insights. Review before running:\n"
        f"#   ansible-playbook mitigation.yml --check --diff\n"
    )


# ---- curated templates (real, tested module calls; vars flagged for the user) ----

_RHEL_KPATCH = """\
- name: Apply kernel live patch (no reboot) for __CVE__
  hosts: "{{ target_hosts | default('all') }}"
  become: true
  vars:
    # Live patching must be enabled and a patch published for this kernel.
    kpatch_stream: "{{ ansible_facts['distribution_version'] }}"
  tasks:
    - name: Ensure kernel live patching tooling is present
      ansible.builtin.dnf:
        name:
          - kpatch
          - kpatch-dnf
        state: present
    - name: Subscribe this kernel to its live-patch stream
      ansible.builtin.command: kpatch-dnf install-patch
      register: kpatch_install
      changed_when: "'Installed' in kpatch_install.stdout"
    - name: Show active live patches (evidence the CVE is closed without a reboot)
      ansible.builtin.command: kpatch list
      register: kpatch_list
      changed_when: false
    - name: Report
      ansible.builtin.debug:
        var: kpatch_list.stdout_lines
"""

_RHEL_SELINUX = """\
- name: Contain the vulnerable service with SELinux for __CVE__
  hosts: "{{ target_hosts | default('all') }}"
  become: true
  vars:
    # OPTIONAL: an SELinux boolean to turn OFF to remove the exploitable behaviour
    # (leave empty to only enforce confinement). e.g. httpd_can_network_connect
    selinux_boolean: ""
  tasks:
    - name: Keep SELinux enforcing (targeted policy confines services)
      ansible.posix.selinux:
        policy: targeted
        state: enforcing
    - name: Disable the risky SELinux boolean, if one applies
      ansible.posix.seboolean:
        name: "{{ selinux_boolean }}"
        state: false
        persistent: true
      when: selinux_boolean | length > 0
"""

_RHEL_FIREWALLD = """\
- name: Remove network exposure with firewalld for __CVE__
  hosts: "{{ target_hosts | default('all') }}"
  become: true
  vars:
    blocked_port: "PORT/tcp"   # FILL IN: the vulnerable service port, e.g. 8080/tcp
    firewalld_zone: public
  tasks:
    - name: Assert the port has been set
      ansible.builtin.assert:
        that: "'PORT' not in blocked_port"
        fail_msg: "Set blocked_port to the real service port before running."
    - name: Block inbound access to the vulnerable port (reversible, no app change)
      ansible.posix.firewalld:
        port: "{{ blocked_port }}"
        zone: "{{ firewalld_zone }}"
        permanent: true
        immediate: true
        state: disabled
"""

_RHEL_DISABLE = """\
- name: Disable the vulnerable service/feature for __CVE__
  hosts: "{{ target_hosts | default('all') }}"
  become: true
  vars:
    vulnerable_service: "SERVICE"   # FILL IN: unit to mask, e.g. cups.service
  tasks:
    - name: Assert the service has been set
      ansible.builtin.assert:
        that: vulnerable_service != 'SERVICE'
        fail_msg: "Set vulnerable_service to the unit to disable before running."
    - name: Stop and mask the vulnerable unit (removes the exposed code path)
      ansible.builtin.systemd:
        name: "{{ vulnerable_service }}"
        state: stopped
        enabled: false
        masked: true
"""

_OS_SCC = """\
- name: Restrict container privileges (SCC/SecurityContext) for __CVE__
  hosts: localhost
  connection: local
  gather_facts: false
  vars:
    namespace: "NAMESPACE"       # FILL IN
    workload: "DEPLOYMENT"       # FILL IN: the Deployment to harden
  tasks:
    - name: Assert target has been set
      ansible.builtin.assert:
        that:
          - namespace != 'NAMESPACE'
          - workload != 'DEPLOYMENT'
        fail_msg: "Set namespace and workload before running."
    - name: Drop Linux capabilities the exploit needs (restricted security context)
      kubernetes.core.k8s:
        state: patched
        kind: Deployment
        name: "{{ workload }}"
        namespace: "{{ namespace }}"
        definition:
          spec:
            template:
              spec:
                securityContext:
                  runAsNonRoot: true
                containers:
                  - name: "{{ workload }}"
                    securityContext:
                      allowPrivilegeEscalation: false
                      readOnlyRootFilesystem: true
                      capabilities:
                        drop: ["ALL"]
"""

_OS_NETWORKPOLICY = """\
- name: Isolate the vulnerable pod with a NetworkPolicy for __CVE__
  hosts: localhost
  connection: local
  gather_facts: false
  vars:
    namespace: "NAMESPACE"                 # FILL IN
    pod_selector: {app: "APP_LABEL"}       # FILL IN: labels of the vulnerable pod
  tasks:
    - name: Assert target has been set
      ansible.builtin.assert:
        that: namespace != 'NAMESPACE'
        fail_msg: "Set namespace and pod_selector before running."
    - name: Deny all ingress/egress to the vulnerable pod (attack surface removed)
      kubernetes.core.k8s:
        state: present
        definition:
          apiVersion: networking.k8s.io/v1
          kind: NetworkPolicy
          metadata:
            name: ndvm-isolate-__CVE_SLUG__
            namespace: "{{ namespace }}"
          spec:
            podSelector:
              matchLabels: "{{ pod_selector }}"
            policyTypes: [Ingress, Egress]
"""

_OS_SCALE = """\
- name: Scale down the non-essential vulnerable component for __CVE__
  hosts: localhost
  connection: local
  gather_facts: false
  vars:
    namespace: "NAMESPACE"       # FILL IN
    deployment: "DEPLOYMENT"     # FILL IN: non-critical workload to pause
  tasks:
    - name: Assert target has been set
      ansible.builtin.assert:
        that:
          - namespace != 'NAMESPACE'
          - deployment != 'DEPLOYMENT'
        fail_msg: "Set namespace and deployment before running."
    - name: Scale the vulnerable Deployment to zero (removes exposure while a fix is scheduled)
      kubernetes.core.k8s_scale:
        api_version: apps/v1
        kind: Deployment
        name: "{{ deployment }}"
        namespace: "{{ namespace }}"
        replicas: 0
"""

_OS_ADMISSION = """\
- name: Block the vulnerable image via admission policy for __CVE__
  hosts: localhost
  connection: local
  gather_facts: false
  vars:
    blocked_image_substr: "IMAGE:TAG"   # FILL IN: the vulnerable image ref to reject
  tasks:
    - name: Assert the image has been set
      ansible.builtin.assert:
        that: "'IMAGE:TAG' not in blocked_image_substr"
        fail_msg: "Set blocked_image_substr to the vulnerable image before running."
    - name: Reject scheduling of the vulnerable image cluster-wide
      kubernetes.core.k8s:
        state: present
        definition:
          apiVersion: admissionregistration.k8s.io/v1
          kind: ValidatingAdmissionPolicy
          metadata:
            name: ndvm-block-__CVE_SLUG__
          spec:
            failurePolicy: Fail
            matchConstraints:
              resourceRules:
                - apiGroups: ["apps", ""]
                  apiVersions: ["v1"]
                  operations: ["CREATE", "UPDATE"]
                  resources: ["deployments", "pods"]
            validations:
              - expression: >-
                  !object.spec.template.spec.containers.exists(c,
                  c.image.contains(params.image))
                messageExpression: "'blocked: vulnerable image __CVE__'"
"""

_VEX = """\
- name: Record Red Hat VEX 'not affected' as the mitigation for __CVE__
  hosts: localhost
  connection: local
  gather_facts: false
  tasks:
    - name: No change required — capture VEX evidence for the audit trail
      ansible.builtin.debug:
        msg: >-
          Red Hat's signed VEX marks this product/version known_not_affected for
          __CVE__. The correct action is to make NO change and file the VEX record
          as evidence. Retrieve it from
          https://access.redhat.com/security/data/csaf/v2/vex/
"""

# ---- curated templates for catalog `config`/`compensating` options that used to
# fall to the debug-only scaffold. Keyed by catalog_id (see _TEMPLATES / build).
# ansible.builtin only — no collection needed to run or lint them. ----

_RHEL_SERVICE_RESTART = """\
- name: Apply the userspace fix and restart only the affected service for __CVE__
  hosts: "{{ target_hosts | default('all') }}"
  become: true
  vars:
    affected_package: "__AFFECTED_PACKAGE__"   # FILL IN if not pre-filled: the fixed package, e.g. openssh-server
    affected_service: "__AFFECTED_SERVICE__"   # FILL IN if not pre-filled: the unit to restart, e.g. sshd
  tasks:
    - name: Assert the package and service have been set
      ansible.builtin.assert:
        that:
          - affected_package != 'PACKAGE'
          - affected_service != 'SERVICE'
        fail_msg: Set affected_package and affected_service before running.
    - name: Update only the affected userspace package (not the kernel)
      ansible.builtin.dnf:
        name: "{{ affected_package }}"
        state: latest  # noqa: package-latest -- applying the fixed version is the point
    - name: Restart only the affected service so it runs the patched binary
      ansible.builtin.systemd:
        name: "{{ affected_service }}"
        state: restarted
"""

_RHEL_SYSTEMD_HARDEN = """\
- name: Contain a userspace service with systemd hardening for __CVE__
  hosts: "{{ target_hosts | default('all') }}"
  become: true
  vars:
    affected_service: "SERVICE"   # FILL IN: unit to harden, e.g. myapp.service
  tasks:
    - name: Assert the service has been set
      ansible.builtin.assert:
        that: affected_service != 'SERVICE'
        fail_msg: Set affected_service to the unit to harden before running.
    - name: Ensure the systemd drop-in directory exists
      ansible.builtin.file:
        path: "/etc/systemd/system/{{ affected_service }}.d"
        state: directory
        mode: "0755"
    - name: Add a systemd hardening drop-in (confines the service, no package change)
      ansible.builtin.copy:
        dest: "/etc/systemd/system/{{ affected_service }}.d/10-ndvm-hardening.conf"
        mode: "0644"
        content: |
          [Service]
          ProtectSystem=strict
          NoNewPrivileges=yes
          PrivateTmp=yes
          CapabilityBoundingSet=
    - name: Reload systemd so the drop-in takes effect
      ansible.builtin.systemd:
        daemon_reload: true
    - name: Restart the service under the new confinement
      ansible.builtin.systemd:
        name: "{{ affected_service }}"
        state: restarted
"""

_RHEL_SSHD = """\
- name: Harden OpenSSH to reduce exploitability for __CVE__
  hosts: "{{ target_hosts | default('all') }}"
  become: true
  vars:
    max_startups: "10:30:60"   # tighten the connection-flood window (see linked solution)
    login_grace_time: "30"
  tasks:
    - name: Set MaxStartups in sshd_config (validated before it is saved)
      ansible.builtin.lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^#?\\s*MaxStartups'
        line: "MaxStartups {{ max_startups }}"
        validate: /usr/sbin/sshd -t -f %s
    - name: Set LoginGraceTime in sshd_config (validated before it is saved)
      ansible.builtin.lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^#?\\s*LoginGraceTime'
        line: "LoginGraceTime {{ login_grace_time }}"
        validate: /usr/sbin/sshd -t -f %s
    - name: Reload sshd to apply the hardened settings
      ansible.builtin.systemd:
        name: sshd
        state: reloaded
"""

_RHEL_HTTP = """\
- name: Reduce web-server / HTTP attack surface for __CVE__
  hosts: "{{ target_hosts | default('all') }}"
  become: true
  vars:
    # FILL IN: the httpd directive that turns off the vulnerable protocol/module,
    # e.g. "Protocols http/1.1" to disable HTTP/2.
    hardening_directive: "Protocols http/1.1"
    httpd_service: httpd
  tasks:
    - name: Apply the surface-reduction directive to httpd
      ansible.builtin.copy:
        dest: /etc/httpd/conf.d/zz-ndvm-hardening.conf
        mode: "0644"
        content: "{{ hardening_directive }}\\n"
    - name: Validate the full httpd configuration before reloading
      ansible.builtin.command: /usr/sbin/httpd -t
      changed_when: false
    - name: Reload httpd to apply the change
      ansible.builtin.systemd:
        name: "{{ httpd_service }}"
        state: reloaded
"""

_RHEL_CRYPTO = """\
- name: Raise the system crypto policy to refuse weak algorithms for __CVE__
  hosts: "{{ target_hosts | default('all') }}"
  become: true
  vars:
    crypto_policy: FUTURE   # or DEFAULT:NO-SHA1, or FIPS where required
  tasks:
    - name: Show the current crypto policy
      ansible.builtin.command: update-crypto-policies --show
      register: current_policy
      changed_when: false
    - name: Set the stricter crypto policy
      ansible.builtin.command: "update-crypto-policies --set {{ crypto_policy }}"
      register: set_policy
      changed_when: crypto_policy not in current_policy.stdout
    - name: Remind to restart TLS-using services to adopt the new policy
      ansible.builtin.debug:
        msg: Restart TLS-using services (or re-open sessions) so they pick up the new crypto policy.
"""

_RHEL_CONTAINER_RUNTIME = """\
- name: Confine container runtime socket exposure for __CVE__
  hosts: "{{ target_hosts | default('all') }}"
  become: true
  vars:
    runtime_socket: "/run/podman/podman.sock"   # FILL IN: the runtime API socket
    socket_group: root
  tasks:
    - name: Restrict access to the container runtime socket (removes untrusted reach)
      ansible.builtin.file:
        path: "{{ runtime_socket }}"
        mode: "0660"
        group: "{{ socket_group }}"
"""

_RHEL_INSIGHTS = """\
- name: Apply the reviewed Red Hat Insights remediation playbook for __CVE__
  hosts: localhost
  connection: local
  gather_facts: false
  vars:
    # FILL IN: path to the remediation playbook you generated AND reviewed in Insights.
    insights_playbook: "PLAYBOOK.yml"
  tasks:
    - name: Assert the reviewed Insights playbook path has been set
      ansible.builtin.assert:
        that: insights_playbook != 'PLAYBOOK.yml'
        fail_msg: Generate and review the Insights remediation playbook, then set its path.
    - name: Check the reviewed remediation playbook exists
      ansible.builtin.stat:
        path: "{{ insights_playbook }}"
      register: rem_pb
    - name: Fail early if the remediation playbook is missing
      ansible.builtin.assert:
        that: rem_pb.stat.exists
        fail_msg: "Remediation playbook not found: {{ insights_playbook }}"
    - name: Run the reviewed Insights remediation playbook (dry-run; drop --check to apply)
      ansible.builtin.command: "ansible-playbook {{ insights_playbook }} --check"
      changed_when: false
"""

_OS_ACS = """\
- name: Enforce a Red Hat ACS policy to block the risky deployment for __CVE__
  hosts: localhost
  connection: local
  gather_facts: false
  vars:
    central_url: "https://CENTRAL_HOST:443"   # FILL IN: ACS Central endpoint
    api_token: "API_TOKEN"                    # FILL IN: ACS API token (store in a vault)
    policy_id: "POLICY_ID"                    # FILL IN: the policy to enforce
  tasks:
    - name: Assert ACS connection details have been set
      ansible.builtin.assert:
        that:
          - "'CENTRAL_HOST' not in central_url"
          - api_token != 'API_TOKEN'
          - policy_id != 'POLICY_ID'
        fail_msg: Set central_url, api_token and policy_id before running.
    - name: Turn on build/deploy enforcement for the policy (blocks the vulnerable image)
      ansible.builtin.uri:
        url: "{{ central_url }}/v1/policies/{{ policy_id }}"
        method: PATCH
        headers:
          Authorization: "Bearer {{ api_token }}"
        body_format: json
        body:
          enforcementActions:
            - FAIL_BUILD_ENFORCEMENT
            - FAIL_DEPLOYMENT_CREATE_ENFORCEMENT
        status_code: 200
"""

_RHEL_NFTABLES = """\
- name: Remove network exposure with nftables for __CVE__
  hosts: "{{ target_hosts | default('all') }}"
  become: true
  vars:
    blocked_port: "PORT"          # FILL IN: the vulnerable service port, e.g. 8080
    nft_table: inet ndvm_filter
  tasks:
    - name: Assert the port has been set
      ansible.builtin.assert:
        that: "'PORT' not in blocked_port"
        fail_msg: "Set blocked_port to the real service port before running."
    - name: Ensure the NDVM filter table exists
      ansible.builtin.command: "nft add table {{ nft_table }}"
      register: nft_table_add
      changed_when: nft_table_add.rc == 0
      failed_when: false
    - name: Ensure the input chain exists (hook into the base filter)
      ansible.builtin.command: >-
        nft add chain {{ nft_table }} input
        { type filter hook input priority 0 ; policy accept ; }
      register: nft_chain_add
      changed_when: nft_chain_add.rc == 0
      failed_when: false
    - name: Block inbound access to the vulnerable port (reversible, no app change)
      ansible.builtin.command: >-
        nft add rule {{ nft_table }} input tcp dport {{ blocked_port }} drop
      register: nft_rule_add
      changed_when: nft_rule_add.rc == 0
    - name: Persist the ruleset so it survives a reboot
      ansible.builtin.shell: "nft list ruleset > /etc/sysconfig/nftables.conf"
      changed_when: true
"""

_RHEL_BLACKLIST_MODULE = """\
- name: Unload and blacklist the vulnerable kernel module for __CVE__
  hosts: "{{ target_hosts | default('all') }}"
  become: true
  vars:
    vulnerable_module: "MODULE"   # FILL IN: kernel module name, e.g. cramfs
  tasks:
    - name: Assert the module has been set
      ansible.builtin.assert:
        that: vulnerable_module != 'MODULE'
        fail_msg: "Set vulnerable_module to the module to blacklist before running."
    - name: Blacklist the module so it cannot load again (survives reboot)
      ansible.builtin.copy:
        dest: "/etc/modprobe.d/ndvm-blacklist-{{ vulnerable_module }}.conf"
        mode: "0644"
        content: |
          blacklist {{ vulnerable_module }}
          install {{ vulnerable_module }} /bin/false
    - name: Rebuild the initramfs so the blacklist takes effect on next boot
      ansible.builtin.command: "dracut -f"
      changed_when: true
    - name: Unload the module right now if it is currently loaded (no reboot needed)
      community.general.modprobe:
        name: "{{ vulnerable_module }}"
        state: absent
"""

_RHEL_QUARANTINE = """\
- name: Quarantine the host to a restricted network zone for __CVE__
  hosts: "{{ target_hosts | default('all') }}"
  become: true
  vars:
    quarantine_interface: "eth0"   # FILL IN: the interface to move to the drop zone
  tasks:
    - name: Assert the interface has been set
      ansible.builtin.assert:
        that: quarantine_interface != ''
        fail_msg: "Set quarantine_interface before running."
    - name: Move the interface to firewalld's drop zone (blocks all unsolicited traffic)
      ansible.posix.firewalld:
        zone: drop
        interface: "{{ quarantine_interface }}"
        permanent: true
        immediate: true
        state: enabled
"""

_OCP_EGRESS_POLICY = """\
- name: Restrict egress from the vulnerable workload for __CVE__
  hosts: localhost
  connection: local
  gather_facts: false
  vars:
    namespace: "NAMESPACE"                 # FILL IN
    pod_selector: {app: "APP_LABEL"}       # FILL IN: labels of the vulnerable pod
  tasks:
    - name: Assert target has been set
      ansible.builtin.assert:
        that: namespace != 'NAMESPACE'
        fail_msg: "Set namespace and pod_selector before running."
    - name: Deny all egress from the vulnerable pod except DNS (attack surface removed)
      kubernetes.core.k8s:
        state: present
        definition:
          apiVersion: networking.k8s.io/v1
          kind: NetworkPolicy
          metadata:
            name: ndvm-egress-restrict-__CVE_SLUG__
            namespace: "{{ namespace }}"
          spec:
            podSelector:
              matchLabels: "{{ pod_selector }}"
            policyTypes: [Egress]
            egress:
              - ports:
                  - protocol: UDP
                    port: 53
"""

_OCP_RESTRICTED_V2 = """\
- name: Enforce restricted-v2 Pod Security standards for __CVE__
  hosts: localhost
  connection: local
  gather_facts: false
  vars:
    namespace: "NAMESPACE"       # FILL IN
  tasks:
    - name: Assert target has been set
      ansible.builtin.assert:
        that: namespace != 'NAMESPACE'
        fail_msg: "Set namespace before running."
    - name: Label the namespace to enforce the restricted-v2 Pod Security standard
      kubernetes.core.k8s:
        state: patched
        kind: Namespace
        name: "{{ namespace }}"
        definition:
          metadata:
            labels:
              pod-security.kubernetes.io/enforce: restricted
              pod-security.kubernetes.io/enforce-version: v2
              pod-security.kubernetes.io/audit: restricted
              pod-security.kubernetes.io/warn: restricted
"""

_OCP_IMAGE_POLICY = """\
- name: Enforce signed images only for __CVE__
  hosts: localhost
  connection: local
  gather_facts: false
  vars:
    namespace: "NAMESPACE"       # FILL IN
    image_scope: "IMAGE_SCOPE"   # FILL IN: image ref/repo this policy covers
  tasks:
    - name: Assert target has been set
      ansible.builtin.assert:
        that:
          - namespace != 'NAMESPACE'
          - image_scope != 'IMAGE_SCOPE'
        fail_msg: "Set namespace and image_scope before running."
    - name: Require cosign-signed images for this scope (rejects the vulnerable/unsigned image)
      kubernetes.core.k8s:
        state: present
        definition:
          apiVersion: policy.sigstore.dev/v1beta1
          kind: ClusterImagePolicy
          metadata:
            name: ndvm-require-signed-__CVE_SLUG__
          spec:
            images:
              - glob: "{{ image_scope }}"
            authorities:
              - keyless:
                  url: https://fulcio.sigstore.dev
"""

_OCP_CUT_ROUTE = """\
- name: Cut external Route/Service exposure for __CVE__
  hosts: localhost
  connection: local
  gather_facts: false
  vars:
    namespace: "NAMESPACE"   # FILL IN
    route_name: "ROUTE"      # FILL IN: the Route exposing the vulnerable service
  tasks:
    - name: Assert target has been set
      ansible.builtin.assert:
        that:
          - namespace != 'NAMESPACE'
          - route_name != 'ROUTE'
        fail_msg: "Set namespace and route_name before running."
    - name: Delete the Route (removes external exposure; internal Service still reachable)
      kubernetes.core.k8s:
        state: absent
        kind: Route
        api_version: route.openshift.io/v1
        name: "{{ route_name }}"
        namespace: "{{ namespace }}"
"""

_OCP_QUARANTINE_NODES = """\
- name: Quarantine nodes hosting the vulnerable workload for __CVE__
  hosts: localhost
  connection: local
  gather_facts: false
  vars:
    node_name: "NODE"   # FILL IN: node to cordon/taint
  tasks:
    - name: Assert the node has been set
      ansible.builtin.assert:
        that: node_name != 'NODE'
        fail_msg: "Set node_name before running."
    - name: Cordon the node so no new pods are scheduled on it
      kubernetes.core.k8s:
        state: patched
        kind: Node
        name: "{{ node_name }}"
        definition:
          spec:
            unschedulable: true
    - name: Taint the node so existing pods without an explicit toleration evict
      kubernetes.core.k8s:
        state: patched
        kind: Node
        name: "{{ node_name }}"
        definition:
          spec:
            taints:
              - key: ndvm.io/quarantine
                value: __CVE_SLUG__
                effect: NoExecute
"""

_OCP_ROLL_IMAGE = """\
- name: Roll a fixed image via a rolling update for __CVE__
  hosts: localhost
  connection: local
  gather_facts: false
  vars:
    namespace: "NAMESPACE"           # FILL IN
    deployment: "DEPLOYMENT"         # FILL IN: the Deployment to roll
    container_name: "CONTAINER"      # FILL IN: the container to update
    fixed_image: "IMAGE:FIXED_TAG"   # FILL IN: the fixed image ref (with digest/tag)
  tasks:
    - name: Assert target has been set
      ansible.builtin.assert:
        that:
          - namespace != 'NAMESPACE'
          - deployment != 'DEPLOYMENT'
          - fixed_image != 'IMAGE:FIXED_TAG'
        fail_msg: "Set namespace, deployment, container_name and fixed_image before running."
    - name: Roll to the fixed image with a controlled, no-reboot rolling update
      kubernetes.core.k8s:
        state: patched
        kind: Deployment
        name: "{{ deployment }}"
        namespace: "{{ namespace }}"
        definition:
          spec:
            strategy:
              type: RollingUpdate
              rollingUpdate:
                maxUnavailable: 1
                maxSurge: 1
            template:
              spec:
                containers:
                  - name: "{{ container_name }}"
                    image: "{{ fixed_image }}"
    - name: Wait for the rollout to complete before declaring the CVE closed
      kubernetes.core.k8s_info:
        kind: Deployment
        name: "{{ deployment }}"
        namespace: "{{ namespace }}"
      register: rollout
      until: >-
        rollout.resources[0].status.updatedReplicas | default(0) ==
        rollout.resources[0].spec.replicas | default(1)
      retries: 30
      delay: 10
"""

_OCP_SECCOMP = """\
- name: Enforce the RuntimeDefault seccomp profile for __CVE__
  hosts: localhost
  connection: local
  gather_facts: false
  vars:
    namespace: "NAMESPACE"       # FILL IN
    workload: "DEPLOYMENT"       # FILL IN: the Deployment to confine
  tasks:
    - name: Assert target has been set
      ansible.builtin.assert:
        that:
          - namespace != 'NAMESPACE'
          - workload != 'DEPLOYMENT'
        fail_msg: "Set namespace and workload before running."
    - name: Apply the RuntimeDefault seccomp profile (blocks the exploit's syscalls)
      kubernetes.core.k8s:
        state: patched
        kind: Deployment
        name: "{{ workload }}"
        namespace: "{{ namespace }}"
        definition:
          spec:
            template:
              spec:
                securityContext:
                  seccompProfile:
                    type: RuntimeDefault
"""

_OCP_CORDON_DRAIN = """\
- name: Shift workloads off the vulnerable node (cordon & drain) for __CVE__
  hosts: localhost
  connection: local
  gather_facts: false
  vars:
    node_name: "NODE"   # FILL IN: the vulnerable node to evacuate onto patched nodes
  tasks:
    - name: Assert the node has been set
      ansible.builtin.assert:
        that: node_name != 'NODE'
        fail_msg: "Set node_name before running."
    - name: Cordon and drain the node so pods reschedule onto patched/unaffected nodes
      kubernetes.core.k8s_drain:
        name: "{{ node_name }}"
        state: drain
        delete_options:
          ignore_daemonsets: true
          delete_emptydir_data: true
          wait_timeout: 120
"""

_OCP_NODE_UPDATE = """\
- name: Roll fixed nodes via MachineConfig behind a PodDisruptionBudget for __CVE__
  hosts: localhost
  connection: local
  gather_facts: false
  vars:
    namespace: "NAMESPACE"                 # FILL IN: the workload's namespace
    pod_selector: {app: "APP_LABEL"}       # FILL IN: labels of the pods that must stay up
    min_available: 1                       # keep at least this many replicas during node drains
    machine_config_pool: worker            # the MCP the fix rolls through (worker/master)
  tasks:
    - name: Assert targets have been set
      ansible.builtin.assert:
        that: namespace != 'NAMESPACE'
        fail_msg: "Set namespace and pod_selector before running."
    - name: Protect the workload during rolling node reboots with a PodDisruptionBudget
      kubernetes.core.k8s:
        state: present
        definition:
          apiVersion: policy/v1
          kind: PodDisruptionBudget
          metadata:
            name: ndvm-pdb-__CVE_SLUG__
            namespace: "{{ namespace }}"
          spec:
            minAvailable: "{{ min_available }}"
            selector:
              matchLabels: "{{ pod_selector }}"
    - name: Wait for the Machine Config Operator to finish rolling the fixed nodes
      kubernetes.core.k8s_info:
        api_version: machineconfiguration.openshift.io/v1
        kind: MachineConfigPool
        name: "{{ machine_config_pool }}"
      register: mcp
      until: >-
        mcp.resources[0].status.machineCount | default(0) ==
        mcp.resources[0].status.updatedMachineCount | default(-1)
      retries: 60
      delay: 30
"""

# platform, action_type -> template. Title keywords disambiguate the OpenShift
# 'config' options (SCC vs admission policy). Entries keyed by catalog_id are
# selected directly by build_playbook when the recommended option matches — every
# non-VEX catalog_id maps directly here so a curated catalog option NEVER falls to
# the debug-only scaffold, even if the caller's platform classification is wrong.
_TEMPLATES = {
    "rhel_kpatch": _RHEL_KPATCH,
    "rhel_selinux": _RHEL_SELINUX,
    "rhel_firewalld": _RHEL_FIREWALLD,
    "rhel_disable": _RHEL_DISABLE,
    "os_scc": _OS_SCC,
    "os_networkpolicy": _OS_NETWORKPOLICY,
    "os_scale": _OS_SCALE,
    "os_admission": _OS_ADMISSION,
    "vex": _VEX,
    # keyed by catalog_id (data/mitigations/{rhel,openshift}.yaml `id:` fields) —
    # every curated option gets its own real, tested template, not a scaffold.
    "rhel_service_restart": _RHEL_SERVICE_RESTART,
    "rhel_systemd_harden": _RHEL_SYSTEMD_HARDEN,
    "rhel_openssh_harden": _RHEL_SSHD,
    "rhel_http_surface": _RHEL_HTTP,
    "rhel_crypto_policy": _RHEL_CRYPTO,
    "rhel_container_runtime": _RHEL_CONTAINER_RUNTIME,
    "rhel_insights_remediation": _RHEL_INSIGHTS,
    "rhel_nftables": _RHEL_NFTABLES,
    "rhel_disable_module": _RHEL_DISABLE,
    "rhel_blacklist_module": _RHEL_BLACKLIST_MODULE,
    "rhel_openssl_isolate": _RHEL_FIREWALLD,
    "rhel_quarantine": _RHEL_QUARANTINE,
    "ocp_acs_policy": _OS_ACS,
    "ocp_networkpolicy": _OS_NETWORKPOLICY,
    "ocp_egress_policy": _OCP_EGRESS_POLICY,
    "ocp_scc": _OS_SCC,
    "ocp_restricted_v2": _OCP_RESTRICTED_V2,
    "ocp_admission_block": _OS_ADMISSION,
    "ocp_image_policy": _OCP_IMAGE_POLICY,
    "ocp_cut_route": _OCP_CUT_ROUTE,
    "ocp_scale_zero": _OS_SCALE,
    "ocp_pause_operator": _OS_SCALE,
    "ocp_default_deny": _OS_NETWORKPOLICY,
    "ocp_quarantine_nodes": _OCP_QUARANTINE_NODES,
    "ocp_roll_image": _OCP_ROLL_IMAGE,
    "ocp_seccomp": _OCP_SECCOMP,
    "ocp_cordon_drain": _OCP_CORDON_DRAIN,
    "ocp_node_update": _OCP_NODE_UPDATE,
}


def _resolve(platform, action_type, title):
    """Pick a template id from the recommended option. Returns 'scaffold' when no
    curated template fits (the LLM synthesised an option outside the catalog).
    action_type wins; title keywords only break ties within that type."""
    t = (title or "").lower()
    a = (action_type or "").lower()
    if a == "verify" or "vex" in t or "not affected" in t:
        return "vex"
    if platform == "openshift":
        if a == "disable":
            return "os_scale"
        if a == "network":
            return "os_networkpolicy"
        if a == "config":
            if "admission" in t or "image" in t:
                return "os_admission"
            return "os_scc"
        if "admission" in t or "image" in t:
            return "os_admission"
        if "scc" in t or "security context" in t:
            return "os_scc"
        if "networkpolicy" in t or "network policy" in t:
            return "os_networkpolicy"
        if "scale" in t:
            return "os_scale"
    if platform == "rhel":
        if a == "livepatch":
            return "rhel_kpatch"
        if a == "selinux":
            return "rhel_selinux"
        if a == "network":
            return "rhel_firewalld"
        if a == "disable":
            return "rhel_disable"
        if "kpatch" in t or "live patch" in t or "livepatch" in t:
            return "rhel_kpatch"
        if "selinux" in t:
            return "rhel_selinux"
        if "firewall" in t:
            return "rhel_firewalld"
        if "disable" in t:
            return "rhel_disable"
    return "scaffold"


def _scaffold(title, steps, cve):
    """Valid, runnable playbook that records the option's own documented steps.
    Used when no curated template matches — honest about being a checklist, not a
    tested module call."""
    tasks = []
    for i, step in enumerate(steps or ["(no explicit steps were provided)"], 1):
        safe = str(step).replace('"', "'").strip()
        tasks.append(
            f'    - name: "Step {i}"\n'
            f'      ansible.builtin.debug:\n'
            f'        msg: "{safe}"\n')
    body = "".join(tasks) or "    - name: No steps\n      ansible.builtin.debug: {msg: none}\n"
    # Quote the play name — LLM titles often contain ':' which breaks YAML otherwise.
    safe_title = str(title or "mitigation").replace('"', "'")
    return (
        f'- name: "{safe_title} (documented steps for __CVE__)"\n'
        f"  hosts: \"{{{{ target_hosts | default('all') }}}}\"\n"
        f"  become: true\n"
        f"  gather_facts: false\n"
        f"  tasks:\n" + body)


def _slug(cve):
    return (cve or "cve").lower().replace(":", "-").replace(" ", "")


# Well-known RPM package -> the systemd unit it ships, for the handful of
# packages whose service name doesn't match the package name. Deliberately
# small and conservative: if a package isn't listed here, we leave the
# service as a FILL-IN rather than guess wrong — a bad guess is worse than an
# honest blank the operator must confirm.
_KNOWN_SERVICES = {
    "openssh-server": "sshd",
    "openssh": "sshd",
    "bind": "named",
    "chrony": "chronyd",
    "ntp": "ntpd",
    "postfix": "postfix",
    "httpd": "httpd",
    "nginx": "nginx",
    "rsyslog": "rsyslog",
    "tuned": "tuned",
    "NetworkManager": "NetworkManager",
}


def _package_from_nvra(nvra):
    """Derive the plain package name from a Red Hat NVR/NVRA string, e.g.
    "openssh-server-8.9p1-3.el9.x86_64" -> "openssh-server",
    "kernel-0:4.18.0-477.27.1.el8_8" -> "kernel". Returns '' if it doesn't
    look like an NVR at all (never guesses)."""
    s = (nvra or "").strip()
    if not s:
        return ""
    tokens = s.split("-")
    for i in range(1, len(tokens)):
        if re.match(r"^\d", tokens[i]) or re.match(r"^\d+:", tokens[i]):
            return "-".join(tokens[:i])
    return ""


def _service_for_package(pkg):
    """Real, known data only: a package's systemd unit if (and only if) we
    have a confident mapping — else ''. Never invents one."""
    return _KNOWN_SERVICES.get(pkg, "")


def _build_play(*, platform, action_type, title, steps, cve, catalog_id, fixed_nvra=""):
    """Resolve + render just the play body (no header). Returns (template_id, play_yaml)."""
    tid = catalog_id if catalog_id in _TEMPLATES else _resolve(platform, action_type, title)
    play = _scaffold(title, steps, cve) if tid == "scaffold" else _TEMPLATES[tid]
    # Substitute on both paths — the scaffold bakes __CVE__ into its play name too.
    play = play.replace("__CVE_SLUG__", _slug(cve)).replace("__CVE__", cve or "the reported CVE")
    if tid == "rhel_service_restart":
        pkg = _package_from_nvra(fixed_nvra)
        svc = _service_for_package(pkg) if pkg else ""
        play = (play.replace("__AFFECTED_PACKAGE__", pkg or "PACKAGE")
                    .replace("__AFFECTED_SERVICE__", svc or "SERVICE"))
    return tid, play


def build_playbook(*, platform, action_type, title, steps, source_urls,
                   cve="", fix_state="", rhsa="", product="", version="",
                   catalog_id="", fixed_nvra="") -> str:
    """Recommended option -> a valid Ansible playbook string (Insights-format
    header + one play).

    Deterministic and grounded: curated catalog options render a real, tested
    template; everything else renders a scaffold of the option's documented
    steps. The whole document is rendered in process in the Red Hat Insights
    Remediations playbook format (one curated template per known issue), using
    NDVM's own non-disruptive catalog instead of upstream's dnf-upgrade-only
    CVE resolution. Never returns invalid YAML and never invents concrete
    values it can't know — those surface as FILL-IN vars guarded by an assert.

    catalog_id, when it names a curated template, selects it directly — the
    robust path (stable ids), falling back to the platform/action_type/title
    heuristic. The one exception to "no invented values": fixed_nvra, when it
    names a package NDVM has grounded evidence for (the pipeline's own
    VulnFinding, never an LLM guess), lets the rhel_service_restart template
    pre-fill the real affected_package/affected_service instead of a FILL-IN
    placeholder — still only when the service mapping is known with confidence
    (see _service_for_package).
    """
    tid, play = _build_play(platform=platform, action_type=action_type, title=title,
                            steps=steps, cve=cve, catalog_id=catalog_id,
                            fixed_nvra=fixed_nvra)
    header = _header(title, cve, fix_state, rhsa, product, version, source_urls, tid)
    return header + "\n" + play


if __name__ == "__main__":
    # Self-check: every template (and the scaffold) must be well-formed YAML that
    # parses to a one-play list with tasks — a broken template would ship a
    # playbook David can't run.
    import yaml  # dev-only; not required in the orchestrator image at runtime

    cases = [
        ("rhel", "livepatch", "Apply a kernel live patch (kpatch)"),
        ("rhel", "selinux", "Tighten SELinux confinement"),
        ("rhel", "network", "Restrict exposure with firewalld"),
        ("rhel", "disable", "Disable the vulnerable module or feature"),
        ("rhel", "verify", 'Confirm "not affected" via Red Hat VEX'),
        ("openshift", "network", "Isolate workloads with a NetworkPolicy"),
        ("openshift", "config", "Tighten the Security Context Constraint (SCC)"),
        ("openshift", "config", "Block the image/version with an admission policy"),
        ("openshift", "disable", "Scale down the non-essential vulnerable component"),
        ("other", "custom", "Some synthesised option"),  # -> scaffold
        ("other", "custom", "Restrict port: 8080"),  # colon in title must stay valid YAML
    ]
    expected_ids = ["rhel_kpatch", "rhel_selinux", "rhel_firewalld", "rhel_disable",
                    "vex", "os_networkpolicy", "os_scc", "os_admission", "os_scale",
                    "scaffold", "scaffold"]
    all_pbs = []  # every generated playbook feeds the ansible-lint gate below
    for (plat, at, title), want in zip(cases, expected_ids):
        assert _resolve(plat, at, title) == want, f"{title!r} -> {_resolve(plat, at, title)} != {want}"
        pb = build_playbook(platform=plat, action_type=at, title=title,
                            steps=["do the first thing", 'quote "this"'],
                            source_urls=["https://access.redhat.com/x"],
                            cve="CVE-2023-3390", fix_state="Fix deferred",
                            rhsa="RHSA-2023:5255", product="RHEL", version="9")
        doc = yaml.safe_load(pb)  # raises on malformed YAML
        assert isinstance(doc, list) and len(doc) == 1, f"{title}: not one play"
        assert doc[0].get("tasks"), f"{title}: no tasks"
        assert "CVE-2023-3390" in pb and "not model-authored" in pb
        assert "__CVE__" not in pb, f"{title}: unsubstituted __CVE__ token"
        all_pbs.append(pb)
    # action_type wins over misleading title keywords
    assert _resolve("openshift", "disable", "admission scale") == "os_scale"
    assert _resolve("rhel", "network", "SELinux firewall combo") == "rhel_firewalld"

    # catalog_id selects a curated template directly for options that used to scaffold.
    id_cases = ["rhel_service_restart", "rhel_systemd_harden", "rhel_openssh_harden",
                "rhel_http_surface", "rhel_crypto_policy", "rhel_container_runtime",
                "rhel_insights_remediation", "ocp_acs_policy",
                "ocp_seccomp", "ocp_cordon_drain", "ocp_node_update"]
    for cid in id_cases:
        pb = build_playbook(platform="rhel", action_type="config", title=cid,
                            steps=[], source_urls=["https://access.redhat.com/x"],
                            cve="CVE-2024-6387", product="RHEL", version="9",
                            catalog_id=cid)
        doc = yaml.safe_load(pb)
        assert isinstance(doc, list) and len(doc) == 1 and doc[0].get("tasks"), f"{cid}: bad play"
        # must be the curated template, NOT the debug-only scaffold, with CVE substituted
        assert "documented-steps scaffold" not in pb, f"{cid}: fell through to scaffold"
        assert "ansible.builtin.debug" not in pb or cid == "rhel_crypto_policy", f"{cid}: debug-only"
        assert "CVE-2024-6387" in pb and "__CVE__" not in pb, f"{cid}: CVE token"
        all_pbs.append(pb)

    # fixed_nvra, when it names a package we confidently know the systemd unit for,
    # pre-fills rhel_service_restart's affected_package/affected_service instead of
    # leaving FILL-IN placeholders (regreSSHion / CVE-2024-6387 real-world case).
    pinned_pb = build_playbook(platform="rhel", action_type="config",
                            title="Restart only the affected service after a userspace fix lands",
                            steps=[], source_urls=["https://access.redhat.com/x"],
                            cve="CVE-2024-6387", product="RHEL", version="9",
                            catalog_id="rhel_service_restart",
                            fixed_nvra="openssh-server-8.7p1-38.el9_4.2")
    assert 'affected_package: "openssh-server"' in pinned_pb, "fixed_nvra pin (package) failed"
    assert 'affected_service: "sshd"' in pinned_pb, "fixed_nvra pin (service) failed"
    assert '"PACKAGE"' not in pinned_pb and '"SERVICE"' not in pinned_pb, "pin left a FILL-IN placeholder"
    all_pbs.append(pinned_pb)
    # ...and without a known fixed_nvra, it still honestly falls back to FILL-IN.
    unpinned_pb = build_playbook(platform="rhel", action_type="config",
                            title="Restart only the affected service after a userspace fix lands",
                            steps=[], source_urls=["https://access.redhat.com/x"],
                            cve="CVE-2024-6387", product="RHEL", version="9",
                            catalog_id="rhel_service_restart")
    assert 'affected_package: "PACKAGE"' in unpinned_pb and 'affected_service: "SERVICE"' in unpinned_pb
    all_pbs.append(unpinned_pb)

    # scaffold must NOT leak a curated module; curated ones must NOT be a debug-only list
    sc = build_playbook(platform="other", action_type="x", title="z", steps=["a"],
                        source_urls=[], cve="CVE-2024-0001")
    assert "documented-steps scaffold" in sc
    assert "CVE-2024-0001" in sc and "__CVE__" not in sc
    all_pbs.append(sc)

    # ansible-lint gate: every generated playbook must pass Ansible best-practice rules.
    # Requires ansible-lint (dev/CI dep). Skips loudly if absent so plain `yaml`-only
    # runs still work; CI installs it and enforces.
    import os
    import shutil
    import subprocess
    import tempfile
    exe = shutil.which("ansible-lint")
    if not exe:
        print("ok (yaml checks passed; ansible-lint NOT installed — lint gate SKIPPED)")
    else:
        cfg = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           ".ansible-lint")
        with tempfile.TemporaryDirectory() as d:
            for i, pb in enumerate(all_pbs):
                with open(os.path.join(d, f"{i:02d}.yml"), "w") as fh:
                    fh.write(pb)
            cmd = [exe, "--profile", "production"]
            if os.path.exists(cfg):
                cmd += ["-c", cfg]
            cmd.append(d)
            r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stdout + r.stderr)
            raise SystemExit(f"ansible-lint gate FAILED ({len(all_pbs)} playbooks)")
        print(f"ok (yaml + ansible-lint gate passed on {len(all_pbs)} playbooks)")
