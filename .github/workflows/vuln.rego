package vuln

failed[msg] {
    input.Results[_].Vulnerabilities[_].VulnerabilityID == "CVE-2020-8164"
    msg := "Denied CVE-2020-8164"
}

failed[msg] {
    cvss := input.Results[_].Vulnerabilities[_].CVSS[_]
    "C:H" == split(cvss.V3Vector, "/")[_]
    msg := "Denied high impact for confidentiality"
}
