package vuln

reasons[msg] {
    src := input.Results[_]
    vuln := src.Vulnerabilities[_]
    vuln.VulnerabilityID == "CVE-2020-8164"
    msg := sprintf("Denied CVE-2020-8164 (%s %s in %s)", [vuln.PkgName, vuln.InstalledVersion, src.Target])
}

reasons[msg] {
    src := input.Results[_]
    vuln := src.Vulnerabilities[_]
    not vuln.VulnerabilityID == "CVE-2020-8164"
    vuln.Severity == "CRITICAL"
    msg := sprintf("Denied CRITICAL (%s %s in %s)", [vuln.PkgName, vuln.InstalledVersion, src.Target])
}

reasons[msg] {
    src := input.Results[_]
    vuln := src.Vulnerabilities[_]
    cvss := vuln.CVSS[_]
    "C:H" == split(cvss.V3Vector, "/")[_]

    msg := sprintf("Denied high impact for confidentiality (%s %s in %s)", [vuln.PkgName, vuln.InstalledVersion, src.Target])
}

reasons[msg] {
    src := input.Results[_]
    src.Type == "bundler"
    pkg := src.Packages[_]
    pkg.Name == "thread_safe"
    pkg.Version == "0.3.6"
    msg := sprintf("Denied thread_safe v0.3.6 in %s", [src.Target])
}

failed = result {
    count(reasons) > 0
    result = {
        "Result": "Failed by custom policy",
        "Reasons": reasons,
    }
}
