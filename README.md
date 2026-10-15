# Get NVD Data

This PowerShell script uses the [NIST NVD API](https://nvd.nist.gov/developers) to search for CVEs, and adds the exploit likelihood (EPSS) from the [FIRST EPSS API](https://www.first.org/epss/api). Results are printed in the terminal: known exploited CVEs (CISA KEV) first, then the rest grouped by severity.

## Author
- [Jose Antonio Teodoro](https://github.com/joseateodoro)

## NAME

    Get-NVDData.ps1 - Search the National Vulnerability Database for CVEs

## SYNOPSIS

    Get-NVDData.ps1 [-CveId cve[,cve...]] [-PassThru]
    Get-NVDData.ps1 [-CweInfo id]
    Get-NVDData.ps1 [-Keyword text] [-Product name | -Cpe cpe] [-Cwe id] [-Severity level] [-Days n] [-KevOnly] [-KevAddedDays n] [-IncludeRejected] [-CweSummary]

## FEATURES

    Known exploited first
        CVEs on CISA's Known Exploited Vulnerabilities (KEV) list are shown in their own section at the top,
        with the date CISA added them (KEV Added) and CISA's patch deadline (KEV Due).

    EPSS exploit likelihood
        Every CVE shows its EPSS score: the chance it is exploited in the next 30 days, from FIRST.
        Within each severity, the CVEs most likely to be exploited are listed first.
        EPSS needs no key. If FIRST cannot be reached, results are shown without it.
        Brand-new CVEs may have no EPSS yet; FIRST scores them once a day.

    CWE and patch links
        Every CVE shows its weakness type (CWE, e.g. CWE-502) and a list of the links NVD tags as patches.

    CWE names
        CWE IDs are matched to their names from MITRE's CWE catalog, e.g. CWE-502 is
        "Deserialization of Untrusted Data". A search ends with a list of every CWE found and its name;
        -CveId results carry them in the 'CWE Names' field.

    CWE search and summary
        -Cwe finds CVEs with a given weakness type. -CweSummary ends a search with a count of CVEs
        per CWE, and how many of them are known exploited, to show which weaknesses a product suffers from.

    CWE sources
        -CveId results show who assigned each CWE in the 'CWE Sources' field: NVD (nvd@nist.gov) or
        the CVE's publisher, often the vendor, as the Primary or a Secondary classification.

    CWE details
        -CweInfo prints everything MITRE's catalog says about one CWE: what it is, related weaknesses,
        platforms, when it is introduced, consequences, detection methods, mitigations, real CVE examples
        and CAPEC attack patterns. It reads MITRE's catalog only, so it needs no NVD key.

    CVE detail view
        -CveId shows each CVE in full: scores and KEV status, description, weaknesses (CWE) with who assigned
        them, NVD's known affected software configurations (products and version ranges, including
        "vulnerable only when running on" combinations), the affected products reported by the vendor on
        CVE.org, and the references to advisories, solutions and tools with their source and tags. Piped on, or with -PassThru, the CVEs are returned as objects instead.

    Product lookup
        -Product turns a plain name such as log4j into NVD's product ID (CPE) and searches every version.

    Rejected CVEs hidden
        CVEs NVD has withdrawn are left out of searches unless -IncludeRejected is given.

    Built-in help
        Get-Help .\Get-NVDData.ps1 -Full     (all parameters)
        Get-Help .\Get-NVDData.ps1 -Examples (examples only)

## OPTIONS

    -CveId
        Looks up one or more CVEs by ID and shows each in detail. Cannot be combined with the search filters.
        Sections:
            Weaknesses (CWE)                             each CWE with its name, and who assigned it
            Known affected software configurations (NVD) products and version ranges NVD lists as vulnerable
            Affected products (CVE.org)                  products and versions as reported by the vendor
            References to advisories, solutions and tools   each URL with its source and tags
                                                         (e.g. Vendor Advisory, Patch, Exploit, US Government Resource)
        Configurations and products show at most 40 lines per CVE, references at most 25; the objects hold the
        full lists. When the output is piped on, the CVEs are returned as objects instead of being shown, with
        the fields 'Affected Configurations', 'Affected Products' and 'References' alongside the CWE, KEV and
        EPSS fields.

        .\Get-NVDData.ps1 -CveId CVE-2021-44228
        .\Get-NVDData.ps1 -CveId CVE-2021-44228, CVE-2021-45046
        .\Get-NVDData.ps1 -CveId CVE-2021-44228 | Export-Csv cves.csv -NoTypeInformation
        .\Get-NVDData.ps1 -CveId CVE-2021-44228 | Select-Object 'CVE ID', 'CWE Names', 'CWE Sources'

        .\Get-NVDData.ps1 -CveId CVE-2021-45046

        === CVE-2021-45046 ===
        Status: Analyzed    Published: 2021-12-14    Last modified: 2026-06-17
        Severity: CRITICAL 9.0 (CVSS 3.1)    EPSS: 100.0%
        Known exploited: added to CISA KEV 2023-05-01, due 2023-05-22
        https://nvd.nist.gov/vuln/detail/CVE-2021-45046

        === Weaknesses (CWE) ===
            CWE-917         Improper Neutralization of Special Elements used in an Expression Language Statement ...
                            Secondary, assigned by security@apache.org
                            Primary, assigned by nvd@nist.gov

        === Known affected software configurations (NVD) ===
            Configuration 1
                apache log4j                             from 2.0.1, before 2.12.2
                apache log4j                             from 2.13.0, before 2.16.0
            ...
            Configuration 3 (vulnerable only in this combination)
                siemens sppa-t3000_ses3000_firmware      all versions
                running on/with: siemens sppa-t3000_ses3000 (hardware)
            ... 68 more lines. Full list: -PassThru, or https://nvd.nist.gov/vuln/detail/CVE-2021-45046

        === Affected products (CVE.org, reported by apache) ===
            Apache Software Foundation - Apache Log4j
                affected: Apache Log4j2 before 2.16.0

        .\Get-NVDData.ps1 -CveId CVE-2026-88771   (references section)

        === References to advisories, solutions and tools (2) ===
            https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697096
                Source: NetScaler    Tags: Vendor Advisory
            https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-88771
                Source: CISA-ADP    Tags: US Government Resource

    -PassThru
        With -CveId, returns the CVEs as objects instead of showing them, e.g. to keep them in a variable.
        Piping the output on does this automatically.

        $cves = .\Get-NVDData.ps1 -CveId CVE-2021-45046 -PassThru
        $cves.'Affected Configurations'

    -Keyword
        Words to find in CVE descriptions. With several words, all must appear.

        .\Get-NVDData.ps1 -Keyword "Microsoft Exchange" -Days 30
        .\Get-NVDData.ps1 -Keyword "remote code execution" -Days 7

    -Product
        A product name, looked up in the NVD product dictionary and searched across every version.
        When the name matches several products, up to 15 are listed so one can be passed to -Cpe.

        .\Get-NVDData.ps1 -Product log4j
        .\Get-NVDData.ps1 -Product log4j -KevOnly

    -Cpe
        A CPE product ID. The full 13-field form matches one version; the short form
        (cpe:2.3:part:vendor:product) matches all versions. Cannot be used with -Product.

        .\Get-NVDData.ps1 -Cpe "cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*"
        .\Get-NVDData.ps1 -Cpe cpe:2.3:a:microsoft:exchange_server -Severity HIGH -Days 90

    -Cwe
        Only CVEs with this weakness type (CWE). Takes the number or the full ID: 79 and CWE-79 are the same.
        One CWE per search. Weakness definitions: https://cwe.mitre.org

        .\Get-NVDData.ps1 -Cwe 79 -Days 7                         # cross-site scripting this week
        .\Get-NVDData.ps1 -Cwe CWE-89 -Severity CRITICAL -Days 30 # critical SQL injection this month
        .\Get-NVDData.ps1 -Cwe 502 -KevOnly                       # exploited deserialization flaws

    -Severity
        Only CVEs with this CVSS v3 severity: LOW, MEDIUM, HIGH or CRITICAL.

        .\Get-NVDData.ps1 -Severity CRITICAL -Days 7

    -Days
        Only CVEs published in the last 1-120 days.

        .\Get-NVDData.ps1 -Days 1
        .\Get-NVDData.ps1 -Days 1 -Severity CRITICAL

    -KevOnly
        Only CVEs on CISA's Known Exploited Vulnerabilities list. The output is the KEV table alone,
        without the CWE list at the end; add -CweSummary to include the CWE counts.

        .\Get-NVDData.ps1 -Product log4j -KevOnly
        .\Get-NVDData.ps1 -Cpe cpe:2.3:a:microsoft:exchange_server -KevOnly

    -KevAddedDays
        Only CVEs CISA added to the KEV list in the last 1-120 days, however old the CVE itself is.
        Use this, not -KevOnly -Days, to see what newly became urgent: -Days filters on when a CVE
        was published, so it misses old CVEs that CISA has only just flagged.

        .\Get-NVDData.ps1 -KevAddedDays 7
        .\Get-NVDData.ps1 -KevAddedDays 10 -KevOnly        # the KEV table only
        .\Get-NVDData.ps1 -KevAddedDays 30 -Severity CRITICAL

    -IncludeRejected
        Include CVEs NVD has rejected (withdrawn). Left out by default.

        .\Get-NVDData.ps1 -Keyword "openssl" -Days 30 -IncludeRejected

    -CweSummary
        Ends a search with a table of the CWEs found: how many CVEs have each, and how many of those are
        known exploited, most common first. A CVE with two CWEs counts under both. Searches only.

        .\Get-NVDData.ps1 -Product log4j -CweSummary
        .\Get-NVDData.ps1 -KevAddedDays 30 -CweSummary

        CWE         CVEs     Known Exploited     Name
        ---         ----     ---------------     ----
        CWE-502     8        1                   Deserialization of Untrusted Data
        CWE-116     4        0                   Improper Encoding or Escaping of Output
        CWE-20      3        1                   Improper Input Validation
        CWE-917     2        2                   Improper Neutralization of Special Elements used in an Expression Language Statement ...

    -CweInfo
        Describes one CWE from MITRE's catalog. Takes the number or the full ID: 502 and CWE-502 are the same.
        Cannot be combined with other parameters. Sections MITRE leaves empty are skipped, and the first 10
        real CVE examples are listed. Categories and deprecated CWEs (e.g. CWE-264, still used on older
        CVEs) are not in the catalog; for those the script gives the MITRE web page instead.

        .\Get-NVDData.ps1 -CweInfo 502    # deserialization of untrusted data
        .\Get-NVDData.ps1 -CweInfo CWE-79 # cross-site scripting

        CWE-502: Deserialization of Untrusted Data
        Abstraction: Base    Status: Draft
        https://cwe.mitre.org/data/definitions/502.html

        === Description ===
            The product deserializes untrusted data without sufficiently ensuring that the resulting data will be valid.

        === Related weaknesses ===
            ChildOf   CWE-913: Improper Control of Dynamically-Managed Code Resources
            PeerOf    CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes

        === Applies to ===
            Java, Ruby, PHP, Python, JavaScript, Not Technology-Specific, ICS/OT (often), AI/ML (often)

        === Potential mitigations ===
            Architecture and Design, Implementation
                If available, use the signing/sealing features of the programming language to assure that
                deserialized data has not been tainted. ...

        (also: Background, Introduced during, Common consequences, Detection methods,
         Observed examples, Related attack patterns (CAPEC), Notes)

## EXAMPLE OUTPUT

    .\Get-NVDData.ps1 -Product log4j -KevOnly

    Product 'log4j' resolved to cpe:2.3:a:apache:log4j

    NVD Vulnerability Search
    Search:  product 'log4j' (cpe:2.3:a:apache:log4j), known exploited only
    Summary: 2 found, 2 known exploited, 2 critical, 0 high

    === Known exploited - CISA KEV (2) ===
    CVE ID             Published      Severity     Score     EPSS       CWE                                   KEV Added      KEV Due
    ------             ---------      --------     -----     ----       ---                                   ---------      -------
    CVE-2021-44228     2021-12-10     CRITICAL     10.0      100.0%     CWE-20, CWE-400, CWE-502, CWE-917     2021-12-10     2021-12-24
    CVE-2021-45046     2021-12-14     CRITICAL     9.0       100.0%     CWE-917                               2023-05-01     2023-05-22

    Patch links:
        CVE-2021-44228    https://msrc-blog.microsoft.com/2021/12/11/microsofts-response-to-cve-2021-44228-apache-log4j2/
                          https://www.oracle.com/security-alerts/cpuapr2022.html
                          https://www.oracle.com/security-alerts/cpujan2022.html
        CVE-2021-45046    https://www.oracle.com/security-alerts/cpujan2022.html

    Without -KevOnly, a search also lists the other CVEs by severity, then ends with a key to the CWEs found:

    === Weaknesses (CWE) ===
        CWE-20      Improper Input Validation
        CWE-400     Uncontrolled Resource Consumption
        CWE-502     Deserialization of Untrusted Data
        CWE-917     Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')

## COMMON USES

    Newly exploited this week            .\Get-NVDData.ps1 -KevAddedDays 7
    Today's critical CVEs                .\Get-NVDData.ps1 -Days 1 -Severity CRITICAL
    Exploited issues in a product        .\Get-NVDData.ps1 -Product log4j -KevOnly
    Serious recent issues in a product   .\Get-NVDData.ps1 -Cpe cpe:2.3:a:microsoft:exchange_server -Severity HIGH -Days 90
    Look up IDs from an advisory         .\Get-NVDData.ps1 -CveId CVE-2021-44228, CVE-2021-45046
    Exploited flaws of one weakness type .\Get-NVDData.ps1 -Cwe 502 -KevOnly
    Weakness profile of a product        .\Get-NVDData.ps1 -Product log4j -CweSummary
    How to prevent a weakness            .\Get-NVDData.ps1 -CweInfo 502

## NOTES

    API key (optional, but without one NVD allows only 5 requests per 30 seconds)
    -Request one at https://nvd.nist.gov/developers/request-an-api-key
    -Save it as nvd.credentials.json next to the script, or ~\.nvd\credentials.json:
        { "ApiKey": "your-nvd-key-here" }
    -Or set $env:NVD_API_KEY

    Requirements
    -PowerShell 7 (tested); Windows PowerShell 5.1 should work but is untested
    -No extra PowerShell modules
    -HTTPS access to services.nvd.nist.gov, api.first.org, cwe.mitre.org and cveawg.mitre.org (CVE.org)

    CWE catalog cache
    -MITRE's CWE catalog is cached in ~\.nvd\ - the only files the script writes:
        cwe-names.csv    (about 56 KB, IDs and names for search results)
        cwe-catalog.csv  (about 3 MB, the full catalog for -CweInfo)
    -Downloaded again from MITRE when the copy is 30 days old
    -If MITRE cannot be reached, an older copy is used, or CWE IDs are shown without names

    Automation
    -On-Prem: Task Scheduler, e.g. a daily run of -KevAddedDays 1

    GUI Link: https://nvd.nist.gov/vuln/search?sortOrder=1&sortDirection=1&resultType=records

    CVE (Common Vulnerabilities and Exposures): is a publicly maintained list of known cybersecurity vulnerabilities. Each entry has a unique identifier (CVE ID), a brief description, and references to advisories or reports. CVE allows organizations to consistently identify and track vulnerabilities across software and systems, facilitating patching and risk management. For example, the Heartbleed bug is listed as CVE-2014-0160, describing a buffer over-read in OpenSSL. 

        - What specific vulnerability exists?

    CPE (Common Platform Enumeration): provides a standardized naming scheme for hardware, software, and operating systems. Each CPE identifier specifies a particular product version, helping security teams determine which systems are affected by a given vulnerability. 

        - Which products or versions are affected?

    CWE (Common Weakness Enumeration): catalogs software and hardware weaknesses that can lead to vulnerabilities. It focuses on the root causes of security issues, such as buffer overflows or improper input validation. CWE helps developers understand why vulnerabilities occur and how to prevent them, serving as a reference for secure coding and mitigation strategies 

        - Why does this vulnerability exist? What is the underlying weakness?
        
## DEVELOPMENT

    Tests (Pester 5 or later; no network access or API key needed)
    -Install once: Install-Module Pester -Scope CurrentUser -SkipPublisherCheck
    -Run from the repository root: Invoke-Pester ./Tests

    Code analysis (PSScriptAnalyzer)
    -Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./PSScriptAnalyzerSettings.psd1
    -The settings file lists the rules deliberately excluded, and why

    Troubleshooting
    -Add -Verbose to any command to see each request and the CWE cache state
