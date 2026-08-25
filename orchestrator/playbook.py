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
def _header(title, cve, fix_state, rhsa, product, version, sources, template_id):
    fixed = f" (fix: {rhsa})" if rhsa else ""
    # version is often already embedded in product ("...Linux 9") — don't repeat it
    parts = [product] + ([version] if version and version not in (product or "") else [])
    prod = " ".join(x for x in parts if x).strip() or "the affected host(s)"
    src = "\n".join(f"#   - {u}" for u in (sources or [])) or "#   - (none)"
    manual = "" if template_id != "scaffold" else (
        "# NOTE: documented-steps scaffold — each task records a manual step for review,\n"
        "#       not a tested module call. Turn steps into real tasks before automating.\n")
    return (
        f"# Non-disruptive mitigation for {cve or 'the reported CVE'}{fixed}\n"
        f"# Option: {title}\n"
        f"# Product: {prod}   |   Red Hat fix_state: {fix_state or 'unknown'}\n"
        f"# Sources:\n{src}\n"
        f"#\n"
        f"# REVIEW before running. Fill the vars below, then dry-run first:\n"
        f"#   ansible-playbook mitigation.yml --check --diff\n"
        f"{manual}"
        f"# Generated deterministically by NDVM — not model-authored.\n"
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
    affected_package: "PACKAGE"   # FILL IN: the fixed package, e.g. openssh-server
    affected_service: "SERVICE"   # FILL IN: the unit to restart, e.g. sshd
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

# platform, action_type -> template. Title keywords disambiguate the OpenShift
# 'config' options (SCC vs admission policy). Entries keyed by catalog_id are
# selected directly by build_playbook when the recommended option matches.
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
    # keyed by catalog_id (was scaffold before):
    "rhel_service_restart": _RHEL_SERVICE_RESTART,
    "rhel_systemd_harden": _RHEL_SYSTEMD_HARDEN,
    "rhel_openssh_harden": _RHEL_SSHD,
    "rhel_http_surface": _RHEL_HTTP,
    "rhel_crypto_policy": _RHEL_CRYPTO,
    "rhel_container_runtime": _RHEL_CONTAINER_RUNTIME,
    "rhel_insights_remediation": _RHEL_INSIGHTS,
    "ocp_acs_policy": _OS_ACS,
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


def build_playbook(*, platform, action_type, title, steps, source_urls,
                   cve="", fix_state="", rhsa="", product="", version="",
                   catalog_id="") -> str:
    """Recommended option -> a valid Ansible playbook string (header + one play).

    Deterministic and grounded: curated catalog options render a real, tested
    template; everything else renders a scaffold of the option's documented steps.
    Never returns invalid YAML and never invents concrete values it can't know —
    those surface as FILL-IN vars guarded by an assert.

    catalog_id, when it names a curated template, selects it directly — the robust
    path (stable ids), falling back to the platform/action_type/title heuristic.
    """
    tid = catalog_id if catalog_id in _TEMPLATES else _resolve(platform, action_type, title)
    play = _scaffold(title, steps, cve) if tid == "scaffold" else _TEMPLATES[tid]
    # Substitute on both paths — the scaffold bakes __CVE__ into its play name too.
    play = play.replace("__CVE_SLUG__", _slug(cve)).replace("__CVE__", cve or "the reported CVE")
    header = _header(title, cve, fix_state, rhsa, product, version, source_urls, tid)
    return header + "---\n" + play


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
                "rhel_insights_remediation", "ocp_acs_policy"]
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
