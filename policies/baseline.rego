package cloudguard

import rego.v1

container_finding(workload, container, rule, severity, title, remediation) := {
 "rule_id": rule, "severity": severity,
 "resource": sprintf("%s/%s", [workload.resource, container.name]),
 "title": title, "recommendation": remediation,
}

findings contains f if {
 some w in input.workloads
 some c in w.containers
 object.get(object.get(c, "securityContext", {}), "privileged", false) == true
 f := container_finding(w, c, "K8S-001", "CRITICAL", "Privileged container", "Set securityContext.privileged to false")
}
findings contains f if {
 some w in input.workloads
 some c in w.containers
 object.get(object.get(c, "securityContext", {}), "allowPrivilegeEscalation", true) != false
 f := container_finding(w, c, "K8S-002", "HIGH", "Privilege escalation is not explicitly disabled", "Set securityContext.allowPrivilegeEscalation to false")
}
findings contains f if {
 some w in input.workloads
 some c in w.containers
 pod_sc := object.get(w.spec, "securityContext", {})
 container_sc := object.get(c, "securityContext", {})
 object.get(container_sc, "runAsNonRoot", object.get(pod_sc, "runAsNonRoot", false)) != true
 f := container_finding(w, c, "K8S-003", "HIGH", "Non-root execution is not enforced", "Set runAsNonRoot=true and use a non-root image")
}
findings contains f if {
 some w in input.workloads
 some c in w.containers
 object.get(object.get(c, "securityContext", {}), "readOnlyRootFilesystem", false) != true
 f := container_finding(w, c, "K8S-004", "MEDIUM", "Writable root filesystem", "Set readOnlyRootFilesystem=true and mount explicit writable volumes")
}
findings contains f if {
 some w in input.workloads
 object.get(w.spec, "hostNetwork", false) == true
 f := {"rule_id":"K8S-005","severity":"HIGH","resource":w.resource,"title":"Host network enabled","recommendation":"Disable hostNetwork unless an approved exception exists"}
}
findings contains f if {
 some w in input.workloads
 some c in w.containers
 limits := object.get(object.get(c, "resources", {}), "limits", {})
 object.get(limits, "cpu", "") == ""
 f := container_finding(w, c, "K8S-006", "MEDIUM", "CPU limit missing", "Set resources.limits.cpu")
}
findings contains f if {
 some w in input.workloads
 some c in w.containers
 limits := object.get(object.get(c, "resources", {}), "limits", {})
 object.get(limits, "memory", "") == ""
 f := container_finding(w, c, "K8S-007", "MEDIUM", "Memory limit missing", "Set resources.limits.memory")
}
findings contains f if {
 some w in input.workloads
 some c in w.containers
 endswith(c.image, ":latest")
 f := container_finding(w, c, "K8S-008", "MEDIUM", "Mutable latest image tag", "Pin the image by digest")
}
findings contains f if {
 some w in input.workloads
 some c in w.containers
 not contains(c.image, "@sha256:")
 segment := array.reverse(split(c.image, "/"))[0]
 not contains(segment, ":")
 f := container_finding(w, c, "K8S-008", "MEDIUM", "Implicit latest image tag", "Pin the image by digest")
}
