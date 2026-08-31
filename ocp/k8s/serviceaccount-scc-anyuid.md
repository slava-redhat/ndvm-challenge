# Postgres (pgvector/pgvector:pg16) and Ollama (ollama/ollama) are upstream
# images that hard-require running as their built-in UID (999 / root) and
# won't start under OpenShift's default "restricted" SCC, which forces an
# arbitrary non-root UID per project. Granting "anyuid" to the ndvm service
# account is the standard workaround for dev/trial projects where you don't
# control the upstream image. Project admins (which trial/sandbox users
# usually are, within their own project) can apply this without cluster-admin:
#
#   oc adm policy add-scc-to-user anyuid -z ndvm -n ${NAMESPACE}
#
# This file documents the requirement; apply it via that command (RoleBinding
# for SCCs cannot be expressed as a plain YAML object applied with `oc apply`
# in all cluster versions, so the script below runs the `oc adm policy`
# command directly instead of applying this file).
