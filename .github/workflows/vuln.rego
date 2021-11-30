package vuln

reasons[msg] {
    input.Results[_].Vulnerabilities[_].VulnerabilityID == "CVE-2020-8164"
    msg := "Denied CVE-2020-8164"
}

reasons[msg] {
    cvss := input.Results[_].Vulnerabilities[_].CVSS[_]
    "C:H" == split(cvss.V3Vector, "/")[_]
    msg := "Denied high impact for confidentiality"
}

reasons[msg] {
    source := input.Results[_]
    source.Type == "bundler"
    pkg := source.Packages[_]
    pkg.Name == "thread_safe"
    pkg.Version == "0.3.6"
    msg := "Denied thread_safe v0.3.6"
}

failed = result {
    count(reasons) > 0
    result = {
        "Result": "Failed by custom policy",
        "Reasons": reasons,
    }
}
