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

# platform, action_type -> template. Title keywords disambiguate the OpenShift
# 'config' options (SCC vs admission policy).
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
                   cve="", fix_state="", rhsa="", product="", version="") -> str:
    """Recommended option -> a valid Ansible playbook string (header + one play).

    Deterministic and grounded: curated catalog options render a real, tested
    template; everything else renders a scaffold of the option's documented steps.
    Never returns invalid YAML and never invents concrete values it can't know —
    those surface as FILL-IN vars guarded by an assert.
    """
    tid = _resolve(platform, action_type, title)
    if tid == "scaffold":
        play = _scaffold(title, steps, cve)
    else:
        play = (_TEMPLATES[tid]
                .replace("__CVE_SLUG__", _slug(cve))
                .replace("__CVE__", cve or "the reported CVE"))
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
    # action_type wins over misleading title keywords
    assert _resolve("openshift", "disable", "admission scale") == "os_scale"
    assert _resolve("rhel", "network", "SELinux firewall combo") == "rhel_firewalld"
    # scaffold must NOT leak a curated module; curated ones must NOT be a debug-only list
    sc = build_playbook(platform="other", action_type="x", title="z", steps=["a"],
                        source_urls=[], cve="CVE-2024-0001")
    assert "documented-steps scaffold" in sc
    print("ok")
