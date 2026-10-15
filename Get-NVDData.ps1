<#
.SYNOPSIS
	Searches the NIST National Vulnerability Database (NVD) for CVEs.

.DESCRIPTION
	Queries the NVD CVE API 2.0 and prints the results in the terminal: known
	exploited CVEs (CISA KEV) first, then the rest grouped by severity. Each CVE
	shows its CVSS score, EPSS exploit likelihood (from FIRST), CWE and patch links.

	-CveId looks CVEs up directly and returns them as objects, so they can be
	piped on. Every other parameter is a search filter; filters combine, and at
	least one is required. Rejected CVEs are left out unless -IncludeRejected.

	The NVD API key is read from the secret NVD_API_KEY in a SecretManagement
	vault (Microsoft.PowerShell.SecretManagement), then from $env:NVD_API_KEY.
	Without a key the script still works, at NVD's slower public rate limit.
	Request a key at https://nvd.nist.gov/developers/request-an-api-key

	CWE names and -CweInfo come from MITRE's CWE catalog, cached in ~\.nvd\
	(cwe-names.csv and cwe-catalog.csv) and downloaded again after 30 days.

.PARAMETER CveId
	One or more CVE IDs to look up directly. Each is shown in detail: scores and
	KEV status, description, weaknesses (CWE) and who assigned them, NVD's known
	affected software configurations, the affected products reported on CVE.org,
	and the references to advisories, solutions and tools (URL, source and tags). When the output is piped on (e.g. to Export-Csv) the CVEs
	are returned as objects instead. Cannot be combined with the filters.

.PARAMETER Keyword
	Words to find in CVE descriptions. With several words, all must appear.

.PARAMETER Product
	A product name, such as log4j. Looked up in the NVD product dictionary and
	searched across every version. When it matches several products, they are
	listed so one can be passed to -Cpe instead.

.PARAMETER Cpe
	A CPE product ID. The full 13-field form matches one version; the short form
	(cpe:2.3:a:vendor:product) matches all versions. Cannot be used with -Product.

.PARAMETER Cwe
	Only CVEs with this weakness type (CWE), e.g. 79 or CWE-79 for cross-site
	scripting. Weakness definitions: https://cwe.mitre.org

.PARAMETER Severity
	Only CVEs with this CVSS v3 severity: LOW, MEDIUM, HIGH or CRITICAL.

.PARAMETER Days
	Only CVEs published in the last 1-120 days.

.PARAMETER KevOnly
	Only CVEs on CISA's Known Exploited Vulnerabilities list. The output is the
	KEV table alone, without the CWE list (add -CweSummary to include counts).

.PARAMETER KevAddedDays
	Only CVEs CISA added to the KEV list in the last 1-120 days, however old the
	CVE itself is. Use this, not -KevOnly -Days, to see what newly became urgent.

.PARAMETER IncludeRejected
	Include CVEs NVD has rejected (withdrawn). They are left out by default.

.PARAMETER CweSummary
	Ends a search with a table of the weakness types (CWEs) found: how many CVEs
	have each, and how many of those are known exploited. Searches only.

.PARAMETER PassThru
	With -CveId, returns the CVEs as objects rather than showing them, e.g. to
	store them in a variable. Piping the output on does this automatically.

.PARAMETER CweInfo
	Describes one CWE, e.g. 502 or CWE-502, from MITRE's catalog: description,
	related weaknesses, platforms, consequences, detection methods, mitigations,
	real CVE examples and attack patterns. Needs no NVD key and stands alone.

.EXAMPLE
	.\Get-NVDData.ps1 -CveId CVE-2021-44228, CVE-2021-45046
	Shows two CVEs in detail, including affected configurations and products.

.EXAMPLE
	$cves = .\Get-NVDData.ps1 -CveId CVE-2021-45046 -PassThru
	Stores the CVE as an object, with every affected configuration.

.EXAMPLE
	.\Get-NVDData.ps1 -CveId CVE-2021-44228 | Export-Csv cves.csv -NoTypeInformation
	Saves looked-up CVEs to a CSV file.

.EXAMPLE
	.\Get-NVDData.ps1 -KevAddedDays 7
	CVEs that CISA listed as actively exploited in the last week.

.EXAMPLE
	.\Get-NVDData.ps1 -Days 1 -Severity CRITICAL
	Critical CVEs published in the last day.

.EXAMPLE
	.\Get-NVDData.ps1 -Product log4j -KevOnly
	Known exploited CVEs in any version of Apache Log4j.

.EXAMPLE
	.\Get-NVDData.ps1 -Cpe cpe:2.3:a:microsoft:exchange_server -Severity HIGH -Days 90
	High-severity Exchange Server CVEs from the last 90 days.

.EXAMPLE
	.\Get-NVDData.ps1 -Cwe 79 -Days 7
	Cross-site scripting (CWE-79) CVEs published in the last week.

.EXAMPLE
	.\Get-NVDData.ps1 -CweInfo 502
	What deserialization of untrusted data is, and how to detect and prevent it.

.EXAMPLE
	.\Get-NVDData.ps1 -Product log4j -CweSummary
	Every Log4j CVE, ending with which weakness types they come from.

.EXAMPLE
	.\Get-NVDData.ps1 -CveId CVE-2021-44228 | Select-Object 'CVE ID', 'CWE Names', 'CWE Sources'
	Shows each CWE's name, and whether NVD or the vendor assigned it.

.EXAMPLE
	.\Get-NVDData.ps1 -Keyword "remote code execution" -Days 7
	CVEs from the last week whose description mentions remote code execution.

.LINK
	https://nvd.nist.gov/developers

.LINK
	https://www.first.org/epss/api
#>
[CmdletBinding()]
Param(
	[Parameter(Mandatory=$false)]
	[ValidatePattern('^CVE-\d{4}-\d{4,}$')]
	[String[]]
	$CveId,

	[Parameter(Mandatory=$false)]
	[String]
	$Keyword,

	[Parameter(Mandatory=$false)]
	[String]
	$Product,

	[Parameter(Mandatory=$false)]
	[String]
	$Cpe,

	[Parameter(Mandatory=$false)]
	[ValidatePattern('^(CWE-)?\d+$')]
	[String]
	$Cwe,

	[Parameter(Mandatory=$false)]
	[ValidateSet('LOW','MEDIUM','HIGH','CRITICAL')]
	[String]
	$Severity,

	[Parameter(Mandatory=$false)]
	[ValidateRange(1,120)]
	[Int]
	$Days,

	[Parameter(Mandatory=$false)]
	[Switch]
	$KevOnly,

	[Parameter(Mandatory=$false)]
	[ValidateRange(1,120)]
	[Int]
	$KevAddedDays,

	[Parameter(Mandatory=$false)]
	[Switch]
	$IncludeRejected,

	[Parameter(Mandatory=$false)]
	[Switch]
	$CweSummary,

	[Parameter(Mandatory=$false)]
	[ValidatePattern('^(CWE-)?\d+$')]
	[String]
	$CweInfo,

	[Parameter(Mandatory=$false)]
	[Switch]
	$PassThru
)


# Checked before anything else, so a mistyped command is answered straight away.
# Without a filter NVD would return its entire catalog of 300,000+ CVEs.
$searchFilterGiven = $Keyword -or $Product -or $Cpe -or $Cwe -or $Severity -or $Days -or $KevOnly -or $KevAddedDays

if (-not ($CveId -or $searchFilterGiven -or $CweInfo)) {
	Write-Host "No filter provided." -ForegroundColor Red
	Write-Host "Use -CveId, -CweInfo, or search with -Keyword, -Product, -Cpe, -Cwe, -Severity, -Days, -KevOnly and/or -KevAddedDays." -ForegroundColor Yellow
	Write-Host "See: Get-Help .\Get-NVDData.ps1 -Examples" -ForegroundColor Yellow
	return
}

# -CweInfo reads MITRE's catalog and never calls NVD, so it stands alone.
if ($CweInfo -and ($CveId -or $searchFilterGiven -or $IncludeRejected -or $CweSummary)) {
	Write-Host "-CweInfo describes one CWE on its own and cannot be combined with other parameters." -ForegroundColor Red
	return
}

if ($CveId -and ($searchFilterGiven -or $IncludeRejected -or $CweSummary)) {
	Write-Host "-CveId looks CVEs up directly and cannot be combined with the search filters." -ForegroundColor Red
	return
}

if ($Product -and $Cpe) {
	Write-Host "Use -Product or -Cpe, not both." -ForegroundColor Red
	return
}

if ($PassThru -and -not $CveId) {
	Write-Host "-PassThru only applies to -CveId." -ForegroundColor Red
	return
}

# NVD expects upper-case IDs; -CveId accepts cve-2021-44228 as well. A separate
# variable keeps the ValidatePattern on $CveId from being re-run.
$resolvedIds = @($CveId | Where-Object { $_ } | ForEach-Object { $_.ToUpperInvariant() } | Select-Object -Unique)

# -Cwe and -CweInfo take 79 or CWE-79; the CWE-79 form is used from here on.
$resolvedCwe = if ($Cwe) { 'CWE-' + ($Cwe -replace '^(?i)CWE-', '') } else { $null }
$resolvedCweInfo = if ($CweInfo) { 'CWE-' + ($CweInfo -replace '^(?i)CWE-', '') } else { $null }

# Windows PowerShell 5.1 may default to older TLS versions that NVD and FIRST refuse.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# The API key is read from a SecretManagement vault, then from $env:NVD_API_KEY
# (for unattended runs where the vault cannot be unlocked). NVD answers without
# a key too, only more slowly. -CweInfo never calls NVD, so it skips the key.
Set-Variable SECRET_NAME -Option Constant -Value 'NVD_API_KEY'
$apiKey = $null
if (-not $CweInfo) {
	if (Get-Command Get-Secret -ErrorAction SilentlyContinue) {
		try {
			$secret = Get-Secret -Name $SECRET_NAME -AsPlainText -ErrorAction Stop
			# A secret saved as a PSCredential comes back as one; its password is the key.
			$apiKey = if ($secret -is [pscredential]) { $secret.GetNetworkCredential().Password } else { [string]$secret }
			Write-Verbose "NVD API key read from secret '$SECRET_NAME'"
		} catch {
			Write-Verbose "Could not read secret '$SECRET_NAME': $($_.Exception.Message)"
		}
	} else {
		Write-Verbose 'Microsoft.PowerShell.SecretManagement is not installed; skipping the vault'
	}
	if ([string]::IsNullOrWhiteSpace($apiKey)) {
		$apiKey = $env:NVD_API_KEY
		if ($apiKey) {
			Write-Verbose 'NVD API key read from $env:NVD_API_KEY'
		}
	}
	if ([string]::IsNullOrWhiteSpace($apiKey)) {
		Write-Host "No NVD API key found. Looked in: secret '$SECRET_NAME' (SecretManagement), `$env:NVD_API_KEY" -ForegroundColor Yellow
		Write-Host "Running with the public rate limit (5 requests per 30 seconds)." -ForegroundColor Yellow
	}
}

Set-Variable API_KEY -Option Constant -Value $apiKey

Set-Variable CVE_URI -Option Constant -Value 'https://services.nvd.nist.gov/rest/json/cves/2.0'
Set-Variable CPE_URI -Option Constant -Value 'https://services.nvd.nist.gov/rest/json/cpes/2.0'

# FIRST's EPSS API: the chance a CVE is exploited in the next 30 days. Public,
# no key, and takes up to 100 CVE IDs per request.
Set-Variable EPSS_URI -Option Constant -Value 'https://api.first.org/data/v1/epss'
Set-Variable EPSS_BATCH_SIZE -Option Constant -Value 100

# MITRE's CWE catalog (view 1000 holds every weakness), cached next to the
# credentials; MITRE updates it a few times a year. Searches only need the
# small names file; -CweInfo reads the full catalog.
Set-Variable CWE_CATALOG_URI -Option Constant -Value 'https://cwe.mitre.org/data/csv/1000.csv.zip'
Set-Variable CWE_CACHE_PATH -Option Constant -Value (Join-Path $HOME '.nvd\cwe-names.csv')
Set-Variable CWE_CATALOG_PATH -Option Constant -Value (Join-Path $HOME '.nvd\cwe-catalog.csv')
Set-Variable CWE_CACHE_DAYS -Option Constant -Value 30

# CVE.org's record of a CVE holds the affected products as reported by the
# organization that published it (the CNA), often the vendor. Public, no key.
Set-Variable CVEORG_URI -Option Constant -Value 'https://cveawg.mitre.org/api/cve'

# How many lines of affected configurations and products -CveId shows per CVE.
# Some CVEs list hundreds; the objects (-PassThru) always hold the full list.
Set-Variable MAX_AFFECTED_LINES -Option Constant -Value 40

# How many references -CveId shows per CVE; the objects hold them all.
Set-Variable MAX_REFERENCES -Option Constant -Value 25

# How many of a CWE's real-world CVE examples -CweInfo lists.
Set-Variable MAX_OBSERVED_EXAMPLES -Option Constant -Value 10

Set-Variable DATE_FORMAT -Option Constant -Value 'yyyy-MM-dd'

# The timestamp format NVD expects for its date filters.
Set-Variable NVD_DATE_FORMAT -Option Constant -Value 'yyyy-MM-ddTHH:mm:ss.fff'

# NVD returns at most 2000 CVEs per page. The CPE API allows more, but 2000
# product entries is plenty to tell which product a name refers to.
Set-Variable RESULTS_PER_PAGE -Option Constant -Value 2000

# NVD allows 50 requests per 30 seconds with a key and 5 without, and asks
# clients to pause between requests either way.
Set-Variable REQUEST_DELAY_SECONDS -Option Constant -Value $(if ($API_KEY) { 1 } else { 6 })

# How many times a throttled (403) or unavailable (503) request is retried.
Set-Variable MAX_RETRIES -Option Constant -Value 5

# How many candidate products are listed when -Product matches several.
Set-Variable MAX_PRODUCT_CHOICES -Option Constant -Value 15

# Blank columns kept between the table columns.
Set-Variable COLUMN_GUTTER -Option Constant -Value 4

# Sends a GET to NVD, retrying with a growing pause when NVD throttles the
# request or is briefly unavailable. Any other failure is thrown to the caller.
function Invoke-NvdRequest($Uri) {
	$headers = @{}
	if ($API_KEY) {
		$headers['apiKey'] = $API_KEY
	}

	for ($attempt = 1; $attempt -le $MAX_RETRIES; $attempt++) {
		try {
			Write-Verbose "NVD request (attempt $attempt): $Uri"
			return Invoke-RestMethod -Uri $Uri -Method Get -Headers $headers -ErrorAction Stop
		} catch {
			$status = [int]$_.Exception.Response.StatusCode
			if ($status -notin @(403, 503) -or $attempt -eq $MAX_RETRIES) {
				throw
			}
			$wait = 6 * $attempt
			Write-Host "NVD returned $status, retrying in $wait seconds ($attempt of $MAX_RETRIES)." -ForegroundColor Yellow
			Start-Sleep -Seconds $wait
		}
	}
}

# Joins a query into key=value pairs. A key whose value is $null is sent on its
# own, which is how NVD expects flags such as hasKev.
function Format-QueryString($Query) {
	$pairs = foreach ($entry in $Query.GetEnumerator()) {
		if ($null -eq $entry.Value) {
			$entry.Key
		} else {
			"$($entry.Key)=$([uri]::EscapeDataString("$($entry.Value)"))"
		}
	}
	return ($pairs -join '&')
}

# Formats a date coming back from the API as yyyy-MM-dd, or '' when it is
# missing or unparseable.
function Format-ApiDate($Value) {
	if ([string]::IsNullOrWhiteSpace("$Value")) {
		return ''
	}

	$parsed = [DateTime]::MinValue
	if ([DateTime]::TryParse("$Value", [ref]$parsed)) {
		return $parsed.ToString($DATE_FORMAT)
	}

	return ''
}

# Turns a product name such as 'log4j' into a partial CPE such as
# cpe:2.3:a:apache:log4j, which matches every version of that product. Returns
# $null after explaining why when the name matches no product, or several, so
# the user can narrow it down rather than search the wrong product.
function Resolve-ProductCpe($Name) {
	$query = [ordered]@{ keywordSearch = $Name; resultsPerPage = $RESULTS_PER_PAGE }
	$response = Invoke-NvdRequest "$CPE_URI`?$(Format-QueryString $query)"

	# Every version of a product has its own CPE entry; the first five fields
	# (cpe, 2.3, part, vendor, product) are what the versions share.
	$candidates = @($response.products |
		Where-Object { -not $_.cpe.deprecated } |
		ForEach-Object {
			[PSCustomObject]@{
				Cpe   = (($_.cpe.cpeName -split ':')[0..4] -join ':')
				Title = ($_.cpe.titles | Where-Object lang -eq 'en' | Select-Object -First 1).title
			}
		} |
		Group-Object Cpe |
		Sort-Object Count -Descending)

	if (-not $candidates) {
		Write-Host "No product in the NVD CPE dictionary matches '$Name'." -ForegroundColor Red
		return $null
	}

	if ($candidates.Count -eq 1) {
		return $candidates[0].Name
	}

	# Several products mention the name. One whose product field is the name
	# itself ('log4j' rather than 'log4j-core') is taken as the one meant.
	$normalizedName = $Name.Trim().ToLowerInvariant() -replace '\s+', '_'
	$exact = @($candidates | Where-Object { ($_.Name -split ':')[4] -eq $normalizedName })
	if ($exact.Count -eq 1) {
		return $exact[0].Name
	}

	Write-Host "'$Name' matches $($candidates.Count) products. Rerun with -Cpe and one of these:" -ForegroundColor Yellow
	$candidates | Select-Object -First $MAX_PRODUCT_CHOICES | ForEach-Object {
		Write-Host ("    {0,-50} {1} version(s), e.g. {2}" -f $_.Name, $_.Count, $_.Group[0].Title) -ForegroundColor Yellow
	}
	if ($candidates.Count -gt $MAX_PRODUCT_CHOICES) {
		Write-Host "    ... and $($candidates.Count - $MAX_PRODUCT_CHOICES) more. A more specific -Product narrows the list." -ForegroundColor Yellow
	}
	return $null
}

# Adds an NVD date filter covering the last $Days days, e.g. pubStartDate and
# pubEndDate for the prefix 'pub'.
function Add-DateRange($Query, $Prefix, $Days) {
	$now = (Get-Date).ToUniversalTime()
	$Query["${Prefix}StartDate"] = $now.AddDays(-$Days).ToString($NVD_DATE_FORMAT)
	$Query["${Prefix}EndDate"] = $now.ToString($NVD_DATE_FORMAT)
}

# Builds the CVE search from the script's filters. A full 13-field CPE names
# one product version (cpeName); anything shorter, such as cpe:2.3:a:apache:log4j,
# matches every version (virtualMatchString).
function Get-SearchQuery($CpeFilter) {
	$query = [ordered]@{}

	if ($Keyword) {
		$query['keywordSearch'] = $Keyword
	}

	if ($CpeFilter) {
		if (($CpeFilter -split ':').Count -eq 13) {
			$query['cpeName'] = $CpeFilter
		} else {
			$query['virtualMatchString'] = $CpeFilter
		}
	}

	if ($resolvedCwe) {
		$query['cweId'] = $resolvedCwe
	}

	if ($Severity) {
		$query['cvssV3Severity'] = $Severity
	}

	if ($Days) {
		Add-DateRange -Query $query -Prefix 'pub' -Days $Days
	}

	if ($KevOnly) {
		$query['hasKev'] = $null
	}

	# Filters on the date CISA listed the CVE as exploited, not when it was
	# published, so old CVEs that only just became urgent are included.
	if ($KevAddedDays) {
		Add-DateRange -Query $query -Prefix 'kev' -Days $KevAddedDays
	}

	# Rejected CVEs were withdrawn and are only noise in a search.
	if (-not $IncludeRejected) {
		$query['noRejected'] = $null
	}

	return $query
}

# Describes the search in words for the results header.
function Format-SearchDescription($CpeFilter) {
	$parts = @()
	if ($Keyword)         { $parts += "keyword '$Keyword'" }
	if ($Product)         { $parts += "product '$Product' ($CpeFilter)" }
	elseif ($Cpe)         { $parts += "CPE $Cpe" }
	if ($resolvedCwe)     { $parts += "weakness $resolvedCwe" }
	if ($Severity)        { $parts += "CVSS v3 severity $Severity" }
	if ($Days)            { $parts += "published in the last $Days day(s)" }
	if ($KevOnly)         { $parts += "known exploited only" }
	if ($KevAddedDays)    { $parts += "added to CISA KEV in the last $KevAddedDays day(s)" }
	if ($IncludeRejected) { $parts += "rejected CVEs included" }
	return ($parts -join ', ')
}

# Flattens one CVE from the API into a single row. CVSS v3.x is preferred
# because that is what the -Severity filter (cvssV3Severity) matches on.
function ConvertTo-CveRow($Cve) {
	$metric = @($Cve.metrics.cvssMetricV31) + @($Cve.metrics.cvssMetricV30) + @($Cve.metrics.cvssMetricV40) + @($Cve.metrics.cvssMetricV2) |
		Where-Object { $_ } |
		Select-Object -First 1
	$metricSeverity = if ($metric.cvssData.baseSeverity) { $metric.cvssData.baseSeverity } else { $metric.baseSeverity }

	# Every CWE entry with who assigned it: NVD's analysts or the CNA (often the
	# vendor), as the Primary or a Secondary classification.
	$weaknessEntries = @(foreach ($weakness in $Cve.weaknesses) {
		foreach ($description in $weakness.description) {
			"$($description.value) $($weakness.type) $($weakness.source)"
		}
	})

	# NVD-CWE-noinfo and NVD-CWE-Other are placeholders, not weaknesses.
	$cwe = @($Cve.weaknesses |
		ForEach-Object { $_.description.value } |
		Where-Object { $_ -match '^CWE-\d+$' } |
		Select-Object -Unique)

	$patchLinks = @($Cve.references |
		Where-Object { $_.tags -contains 'Patch' } |
		ForEach-Object { $_.url } |
		Select-Object -Unique)

	return [PSCustomObject]@{
		'CVE ID'                  = $Cve.id
		'Published'               = Format-ApiDate $Cve.published
		'Last Modified'           = Format-ApiDate $Cve.lastModified
		'Status'                  = $Cve.vulnStatus
		'CVSS Version'            = $metric.cvssData.version
		'Score'                   = $metric.cvssData.baseScore
		'Severity'                = $metricSeverity
		'EPSS'                    = $null
		'EPSS Percentile'         = $null
		'CWE'                     = $cwe -join ', '
		'CWE Names'               = $null
		'CWE Sources'             = $weaknessEntries -join '; '
		'KEV Added'               = Format-ApiDate $Cve.cisaExploitAdd
		'KEV Due'                 = Format-ApiDate $Cve.cisaActionDue
		'KEV Action'              = $Cve.cisaRequiredAction
		'Patch Links'             = $patchLinks -join ' '
		'Affected Configurations' = Get-AffectedConfigurationText $Cve
		'Affected Products'       = $null
		'References'              = Get-ReferenceText $Cve @{}
		'Description'             = ($Cve.descriptions | Where-Object lang -eq 'en' | Select-Object -First 1).value
		'URL'                     = "https://nvd.nist.gov/vuln/detail/$($Cve.id)"
	}
}

# Looks up each CVE ID on its own. The raw NVD records are kept in
# $script:RawCves by ID, for the detail view's configurations and weaknesses.
function Get-CvesById($Ids) {
	$results = [System.Collections.Generic.List[object]]::new()
	$script:RawCves = @{}
	$processed = 0

	foreach ($id in $Ids) {
		$processed++
		Write-Progress -Activity "Querying NVD" `
			-Status "$id ($processed of $($Ids.Count))" `
			-PercentComplete (($processed / $Ids.Count) * 100)

		$response = Invoke-NvdRequest "$CVE_URI`?$(Format-QueryString ([ordered]@{ cveId = $id }))"
		if (-not $response.vulnerabilities) {
			Write-Host "CVE not found in NVD: $id" -ForegroundColor Red
		}
		foreach ($vulnerability in $response.vulnerabilities) {
			$results.Add((ConvertTo-CveRow $vulnerability.cve))
			$script:RawCves[$vulnerability.cve.id] = $vulnerability.cve
		}

		if ($processed -lt $Ids.Count) {
			Start-Sleep -Seconds $REQUEST_DELAY_SECONDS
		}
	}

	Write-Progress -Activity "Querying NVD" -Completed
	return $results
}

# Runs a search, following NVD's pages until every result is in.
function Search-Cves($Query) {
	$results = [System.Collections.Generic.List[object]]::new()
	$startIndex = 0

	do {
		$pageQuery = [ordered]@{}
		$Query.GetEnumerator() | ForEach-Object { $pageQuery[$_.Key] = $_.Value }
		$pageQuery['resultsPerPage'] = $RESULTS_PER_PAGE
		$pageQuery['startIndex'] = $startIndex

		$response = Invoke-NvdRequest "$CVE_URI`?$(Format-QueryString $pageQuery)"
		foreach ($vulnerability in $response.vulnerabilities) {
			$results.Add((ConvertTo-CveRow $vulnerability.cve))
		}

		$startIndex += $response.resultsPerPage
		Write-Progress -Activity "Querying NVD" `
			-Status "$([Math]::Min($startIndex, $response.totalResults)) of $($response.totalResults) CVEs" `
			-PercentComplete ([Math]::Min(100, ($startIndex / [Math]::Max(1, $response.totalResults)) * 100))

		$morePages = $response.resultsPerPage -gt 0 -and $startIndex -lt $response.totalResults
		if ($morePages) {
			Start-Sleep -Seconds $REQUEST_DELAY_SECONDS
		}
	} while ($morePages)

	Write-Progress -Activity "Querying NVD" -Completed
	return $results
}

# Fills in each row's EPSS score from FIRST, 100 CVEs per request. EPSS is a
# nice-to-have on top of NVD's data, so if FIRST cannot be reached the rows are
# shown without it rather than the whole run failing.
function Add-EpssScores($Rows) {
	$rowList = @($Rows)
	$byId = @{}
	$rowList | ForEach-Object { $byId[$_.'CVE ID'] = $_ }

	for ($start = 0; $start -lt $rowList.Count; $start += $EPSS_BATCH_SIZE) {
		$end = [Math]::Min($start + $EPSS_BATCH_SIZE, $rowList.Count) - 1
		$ids = @($rowList[$start..$end] | ForEach-Object { $_.'CVE ID' })

		Write-Progress -Activity "Querying FIRST EPSS" `
			-Status "$($end + 1) of $($rowList.Count) CVEs" `
			-PercentComplete ((($end + 1) / $rowList.Count) * 100)

		try {
			Write-Verbose "EPSS request for $($ids.Count) CVE(s)"
			$response = Invoke-RestMethod -Uri "$EPSS_URI`?cve=$($ids -join ',')" -Method Get -ErrorAction Stop
		} catch {
			Write-Host "Could not get EPSS scores from FIRST: $($_.Exception.Message)" -ForegroundColor Yellow
			Write-Host "Showing results without EPSS." -ForegroundColor Yellow
			break
		}

		foreach ($score in $response.data) {
			$row = $byId[$score.cve]
			if ($row) {
				$row.EPSS = [double]::Parse($score.epss, [Globalization.CultureInfo]::InvariantCulture)
				$row.'EPSS Percentile' = [double]::Parse($score.percentile, [Globalization.CultureInfo]::InvariantCulture)
			}
		}
	}

	Write-Progress -Activity "Querying FIRST EPSS" -Completed
}

# EPSS as a percentage with one decimal, or '' when FIRST has no score.
function Format-Epss($Value) {
	if ($null -eq $Value) {
		return ''
	}
	return ('{0:0.0}%' -f ($Value * 100))
}

# Downloads MITRE's CWE catalog when there is no cached copy or it is older than
# CWE_CACHE_DAYS, keeping the full catalog plus a small file of IDs and names.
# If MITRE cannot be reached, any older copy stays in place.
function Update-CweCatalog {
	# Refreshing a local cache needs no -WhatIf/-Confirm.
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
	param()

	$cacheIsFresh = [System.IO.File]::Exists($CWE_CACHE_PATH) -and
		[System.IO.File]::Exists($CWE_CATALOG_PATH) -and
		((Get-Date) - (Get-Item $CWE_CACHE_PATH).LastWriteTime).TotalDays -lt $CWE_CACHE_DAYS
	Write-Verbose "CWE catalog cache: $(if ($cacheIsFresh) { 'fresh' } else { 'missing or older than ' + $CWE_CACHE_DAYS + ' days' }) ($CWE_CATALOG_PATH)"

	if (-not $cacheIsFresh) {
		$tempFolder = Join-Path ([System.IO.Path]::GetTempPath()) "cwe-$([guid]::NewGuid())"
		try {
			Write-Host "Downloading the CWE catalog from MITRE..." -ForegroundColor DarkGray
			New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null
			$zipPath = Join-Path $tempFolder 'cwe.csv.zip'
			Invoke-WebRequest -Uri $CWE_CATALOG_URI -OutFile $zipPath -UseBasicParsing -ErrorAction Stop
			Expand-Archive -Path $zipPath -DestinationPath $tempFolder -Force -ErrorAction Stop
			$catalog = Get-ChildItem -Path $tempFolder -Filter '*.csv' | Select-Object -First 1

			New-Item -ItemType Directory -Path (Split-Path $CWE_CACHE_PATH) -Force | Out-Null
			Copy-Item -Path $catalog.FullName -Destination $CWE_CATALOG_PATH -Force
			Import-Csv -Path $catalog.FullName |
				Select-Object @{ Name = 'Id'; Expression = { "CWE-$($_.'CWE-ID')" } }, Name |
				Export-Csv -Path $CWE_CACHE_PATH -NoTypeInformation -Encoding UTF8
		} catch {
			Write-Host "Could not download the CWE catalog from MITRE: $($_.Exception.Message)" -ForegroundColor Yellow
		} finally {
			Remove-Item -Path $tempFolder -Recurse -Force -ErrorAction SilentlyContinue
		}
	}
}

# Returns a table of CWE names keyed by ID ('CWE-79') from the cached catalog.
# Names are a nice-to-have: with no copy at all the table is empty and the
# results show bare IDs.
function Get-CweNames {
	$names = @{}
	Update-CweCatalog

	if ([System.IO.File]::Exists($CWE_CACHE_PATH)) {
		Import-Csv -Path $CWE_CACHE_PATH | ForEach-Object { $names[$_.Id] = $_.Name }
	} else {
		Write-Host "Showing CWE IDs without names." -ForegroundColor Yellow
	}

	return $names
}

# Sorts CWE IDs by number, so CWE-79 comes before CWE-400.
function Get-SortedCweIds($Ids) {
	return @($Ids | Sort-Object { [int]($_ -replace '^CWE-', '') })
}

# 'CWE-79: Improper Neutralization ...', or the bare ID when the name is unknown.
function Format-CweName($Id, $Names) {
	if ($Names[$Id]) {
		return "${Id}: $($Names[$Id])"
	}
	return $Id
}

# Fills in each row's 'CWE Names' from the catalog.
function Add-CweNames($Rows, $Names) {
	foreach ($row in @($Rows)) {
		$ids = Get-SortedCweIds @($row.CWE -split ', ' | Where-Object { $_ })
		$row.'CWE Names' = (@($ids | ForEach-Object { Format-CweName $_ $Names }) -join '; ')
	}
}

# Lists each CWE seen in the results with its name, as a key to the CWE column.
function Format-CweList($Rows, $Names) {
	$ids = Get-SortedCweIds @($Rows | ForEach-Object { $_.CWE -split ', ' } | Where-Object { $_ } | Select-Object -Unique)
	if (-not $ids) {
		return "    (none)"
	}
	return (@($ids | ForEach-Object { "    {0,-12}{1}" -f $_, $Names[$_] }) -join [Environment]::NewLine)
}

# Counts how many CVEs have each CWE, and how many of those are known exploited,
# most common first. A CVE with two CWEs counts under both.
function Format-CweSummary($Rows, $Names) {
	$rowList = @($Rows)

	$entries = foreach ($row in $rowList) {
		foreach ($id in @($row.CWE -split ', ' | Where-Object { $_ })) {
			[PSCustomObject]@{ Id = $id; Exploited = [bool]$row.'KEV Added' }
		}
	}

	$summary = @($entries |
		Group-Object Id |
		ForEach-Object {
			[PSCustomObject]@{
				'CWE'             = $_.Name
				'CVEs'            = $_.Count
				'Known Exploited' = @($_.Group | Where-Object Exploited).Count
				'Name'            = $Names[$_.Name]
			}
		} |
		Sort-Object @{ Expression = 'CVEs'; Descending = $true }, @{ Expression = 'Known Exploited'; Descending = $true })

	$unclassified = @($rowList | Where-Object { -not $_.CWE }).Count

	$lines = @()
	if ($summary) {
		$columns = @(
			@{ Name = 'CWE';             Expression = { Format-TableCell $_.'CWE' 'CWE' } },
			@{ Name = 'CVEs';            Expression = { Format-TableCell $_.'CVEs' 'CVEs' } },
			@{ Name = 'Known Exploited'; Expression = { Format-TableCell $_.'Known Exploited' 'Known Exploited' } },
			@{ Name = 'Name';            Expression = { $_.'Name' } }
		)
		$lines += ($summary | Format-Table $columns -AutoSize | Out-String -Width 500).Trim()
	} else {
		$lines += "    (none)"
	}

	if ($unclassified) {
		$lines += ""
		$lines += "$unclassified CVE(s) have no CWE: NVD has not classified them, or marked them NVD-CWE-noinfo / NVD-CWE-Other."
	}

	return ($lines -join [Environment]::NewLine)
}

# MITRE packs multi-part catalog fields as ::KEY:value:KEY:value:: entries, e.g.
# ::SCOPE:Integrity:IMPACT:Modify Application Data::. Values can hold colons of
# their own ('DoS: Resource Consumption', 'https://...', 'std::auto_ptr'), so
# only the field names in $Keys count as keys, and entries are only split at a
# '::' followed by one of them. Returns one ordered table per entry; a key that
# repeats (several IMPACTs) has its values joined with ', '.
function ConvertFrom-CweField($Text, $Keys) {
	if ([string]::IsNullOrWhiteSpace($Text)) {
		return @()
	}

	$keyPattern = (@($Keys | Sort-Object Length -Descending | ForEach-Object { [regex]::Escape($_) }) -join '|')
	$entries = [regex]::Split($Text, "::(?=(?:$keyPattern):|$)") | Where-Object { $_ }

	foreach ($entry in $entries) {
		$keyMatches = [regex]::Matches($entry, "(?:^|:)(?<key>$keyPattern):")
		$fields = [ordered]@{}
		for ($i = 0; $i -lt $keyMatches.Count; $i++) {
			$start = $keyMatches[$i].Index + $keyMatches[$i].Length
			$end = if ($i + 1 -lt $keyMatches.Count) { $keyMatches[$i + 1].Index } else { $entry.Length }
			$key = $keyMatches[$i].Groups['key'].Value
			$value = $entry.Substring($start, $end - $start).Trim()
			if ($fields.Contains($key)) {
				$fields[$key] += ", $value"
			} else {
				$fields[$key] = $value
			}
		}
		if ($fields.Count) {
			$fields
		}
	}
}

# MITRE runs several development phases together with plain spaces, e.g.
# 'Architecture and Design Implementation'. Picks out its known phase names and
# separates them with commas; text with no known phase is returned as it is.
function Format-CwePhases($Text) {
	$phases = @('Architecture and Design', 'Build and Compilation', 'Patching and Maintenance',
		'Decommissioning and End-of-Life', 'System Configuration', 'Requirements', 'Implementation',
		'Installation', 'Integration', 'Manufacturing', 'Distribution', 'Documentation', 'Operation',
		'Bundling', 'Policy', 'Porting', 'Testing')
	$found = @([regex]::Matches("$Text", ($phases | ForEach-Object { [regex]::Escape($_) }) -join '|') | ForEach-Object { $_.Value })
	if (-not $found) {
		return $Text
	}
	return ($found -join ', ')
}

# Splits a catalog field with no keys, such as ::text::text::, into its parts.
function ConvertFrom-CweList($Text) {
	return @("$Text" -split '::' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

# Word-wraps text to the console width, indenting every line.
function Format-Wrapped($Text, $Indent) {
	$width = try { $Host.UI.RawUI.WindowSize.Width } catch { 0 }
	if ($width -lt 60) {
		$width = 100
	}

	$pad = ' ' * $Indent
	$lines = @()
	$line = ''
	foreach ($word in @("$Text" -split '\s+' | Where-Object { $_ })) {
		if ($line -and ($Indent + $line.Length + 1 + $word.Length) -ge $width) {
			$lines += $pad + $line
			$line = $word
		} elseif ($line) {
			$line += " $word"
		} else {
			$line = $word
		}
	}
	if ($line) {
		$lines += $pad + $line
	}

	return ($lines -join [Environment]::NewLine)
}

# Prints a section heading and its body, or nothing when the body is empty.
function Write-DetailSection($Heading, $Body) {
	if (-not $Body) {
		return
	}
	Write-Host ""
	Write-Host "=== $Heading ===" -ForegroundColor Cyan
	Write-Host ($Body -join [Environment]::NewLine)
}

# Prints everything MITRE's catalog says about one CWE: what it is, where it
# applies, its consequences, how to detect and prevent it, and real CVEs it
# caused. Sections MITRE leaves empty are skipped.
function Show-CweInfo($Id) {
	Update-CweCatalog
	if (-not [System.IO.File]::Exists($CWE_CATALOG_PATH)) {
		Write-Host "The CWE catalog is not available, so $Id cannot be described." -ForegroundColor Red
		Write-Host "See: https://cwe.mitre.org/data/definitions/$($Id -replace '^CWE-', '').html" -ForegroundColor Yellow
		return
	}

	$number = $Id -replace '^CWE-', ''
	$weakness = Import-Csv -Path $CWE_CATALOG_PATH | Where-Object { $_.'CWE-ID' -eq $number } | Select-Object -First 1
	if (-not $weakness) {
		Write-Host "$Id is not a weakness in MITRE's CWE catalog." -ForegroundColor Red
		Write-Host "It may be a category or deprecated, which the catalog leaves out. See: https://cwe.mitre.org/data/definitions/$number.html" -ForegroundColor Yellow
		return
	}

	$names = Get-CweNames

	Write-Host ""
	Write-Host "${Id}: $($weakness.Name)" -ForegroundColor Green
	$facts = @("Abstraction: $($weakness.'Weakness Abstraction')", "Status: $($weakness.Status)")
	if ($weakness.'Likelihood of Exploit') {
		$facts += "Likelihood of exploit: $($weakness.'Likelihood of Exploit')"
	}
	Write-Host ($facts -join '    ')
	Write-Host "https://cwe.mitre.org/data/definitions/$number.html"

	$description = @(Format-Wrapped $weakness.Description 4)
	if ($weakness.'Extended Description') {
		$description += ""
		$description += Format-Wrapped ((ConvertFrom-CweList $weakness.'Extended Description') -join ' ') 4
	}
	Write-DetailSection 'Description' $description

	Write-DetailSection 'Background' @(ConvertFrom-CweList $weakness.'Background Details' | ForEach-Object { Format-Wrapped $_ 4 })

	# The catalog lists relationships in several views; view 1000 is the full tree.
	Write-DetailSection 'Related weaknesses' @(ConvertFrom-CweField $weakness.'Related Weaknesses' @('NATURE', 'CWE ID', 'VIEW ID', 'ORDINAL') |
		Where-Object { $_['VIEW ID'] -eq '1000' } |
		ForEach-Object { "    {0,-10}{1}" -f $_['NATURE'], (Format-CweName "CWE-$($_['CWE ID'])" $names) })

	$platforms = @(ConvertFrom-CweField $weakness.'Applicable Platforms' @(
			'LANGUAGE NAME', 'LANGUAGE CLASS', 'LANGUAGE PREVALENCE',
			'TECHNOLOGY NAME', 'TECHNOLOGY CLASS', 'TECHNOLOGY PREVALENCE',
			'OPERATING SYSTEM NAME', 'OPERATING SYSTEM CLASS', 'OPERATING SYSTEM PREVALENCE',
			'ARCHITECTURE NAME', 'ARCHITECTURE CLASS', 'ARCHITECTURE PREVALENCE') |
		ForEach-Object {
			$entry = $_
			$name = @($entry.Keys | Where-Object { $_ -match '(NAME|CLASS)$' } | ForEach-Object { $entry[$_] }) -join ' '
			$prevalence = @($entry.Keys | Where-Object { $_ -match 'PREVALENCE$' } | ForEach-Object { $entry[$_] }) -join ''
			if ($prevalence -and $prevalence -ne 'Undetermined') { "$name ($($prevalence.ToLowerInvariant()))" } else { $name }
		})
	if ($platforms) {
		Write-DetailSection 'Applies to' @(Format-Wrapped ($platforms -join ', ') 4)
	}

	Write-DetailSection 'Introduced during' @(ConvertFrom-CweField $weakness.'Modes Of Introduction' @('PHASE', 'NOTE') |
		ForEach-Object {
			"    $(Format-CwePhases $_['PHASE'])"
			if ($_['NOTE']) { Format-Wrapped $_['NOTE'] 8 }
		})

	Write-DetailSection 'Common consequences' @(ConvertFrom-CweField $weakness.'Common Consequences' @('SCOPE', 'IMPACT', 'LIKELIHOOD', 'NOTE') |
		ForEach-Object {
			$heading = "    $($_['SCOPE']): $($_['IMPACT'])"
			if ($_['LIKELIHOOD']) { $heading += " (likelihood $($_['LIKELIHOOD']))" }
			$heading
			if ($_['NOTE']) { Format-Wrapped $_['NOTE'] 8 }
		})

	Write-DetailSection 'Detection methods' @(ConvertFrom-CweField $weakness.'Detection Methods' @('METHOD', 'DESCRIPTION', 'EFFECTIVENESS NOTES', 'EFFECTIVENESS') |
		ForEach-Object {
			$heading = "    $($_['METHOD'])"
			if ($_['EFFECTIVENESS']) { $heading += " (effectiveness: $($_['EFFECTIVENESS']))" }
			$heading
			if ($_['DESCRIPTION']) { Format-Wrapped $_['DESCRIPTION'] 8 }
		})

	Write-DetailSection 'Potential mitigations' @(ConvertFrom-CweField $weakness.'Potential Mitigations' @('PHASE', 'STRATEGY', 'DESCRIPTION', 'EFFECTIVENESS NOTES', 'EFFECTIVENESS') |
		ForEach-Object {
			$heading = "    $(Format-CwePhases $_['PHASE'])"
			if ($_['STRATEGY']) { $heading += " - $($_['STRATEGY'])" }
			if ($_['EFFECTIVENESS']) { $heading += " (effectiveness: $($_['EFFECTIVENESS']))" }
			$heading
			if ($_['DESCRIPTION']) { Format-Wrapped $_['DESCRIPTION'] 8 }
		})

	$examples = @(ConvertFrom-CweField $weakness.'Observed Examples' @('REFERENCE', 'DESCRIPTION', 'LINK'))
	$exampleLines = @($examples | Select-Object -First $MAX_OBSERVED_EXAMPLES | ForEach-Object {
		"    $($_['REFERENCE'])"
		Format-Wrapped $_['DESCRIPTION'] 8
	})
	if ($examples.Count -gt $MAX_OBSERVED_EXAMPLES) {
		$exampleLines += "    ... and $($examples.Count - $MAX_OBSERVED_EXAMPLES) more on the MITRE page."
	}
	Write-DetailSection "Observed examples ($($examples.Count))" $exampleLines

	Write-DetailSection 'Related attack patterns (CAPEC)' @(ConvertFrom-CweList $weakness.'Related Attack Patterns' |
		ForEach-Object { "    CAPEC-$_    https://capec.mitre.org/data/definitions/$_.html" })

	Write-DetailSection 'Notes' @(ConvertFrom-CweField $weakness.'Notes' @('TYPE', 'NOTE') |
		ForEach-Object {
			"    $($_['TYPE'])"
			Format-Wrapped $_['NOTE'] 8
		})

	Write-Host ""
}

# Turns one NVD cpeMatch entry into 'vendor product' and its versions, e.g.
# 'apache log4j    from 2.0.1, before 2.12.2'.
function Format-CpeMatch($Match) {
	# CPE fields: cpe, 2.3, part, vendor, product, version, update, ... A colon
	# inside a field is escaped as '\:'.
	$fields = $Match.criteria -split '(?<!\\):'
	$name = ("$($fields[3]) $($fields[4])" -replace '\\', '')
	$version = $fields[5]
	$update = $fields[6]

	$range = @()
	if ($Match.versionStartIncluding) { $range += "from $($Match.versionStartIncluding)" }
	if ($Match.versionStartExcluding) { $range += "after $($Match.versionStartExcluding)" }
	if ($Match.versionEndExcluding)   { $range += "before $($Match.versionEndExcluding)" }
	if ($Match.versionEndIncluding)   { $range += "up to and including $($Match.versionEndIncluding)" }

	# No range: the CPE names one version itself. '*' is any version and '-'
	# means versions do not apply, as for most hardware.
	if (-not $range) {
		if ($version -eq '*') {
			$range += 'all versions'
		} elseif ($version -ne '-') {
			$text = "version $version"
			if ($update -notin @('*', '-')) {
				$text += " $update"
			}
			$range += $text
		}
	}

	if ($fields[2] -eq 'h') {
		$name += ' (hardware)'
	}

	# Edition, language, software edition, target software, target hardware and
	# other: shown when set, so entries such as a FIPS edition stay distinguishable.
	$qualifiers = @($fields[7..12] | Where-Object { $_ -and $_ -notin @('*', '-') } | ForEach-Object { $_ -replace '\\', '' })
	$versions = $range -join ', '
	if ($qualifiers) {
		$versions += " [$($qualifiers -join ', ')]"
	}

	return ("{0,-40} {1}" -f $name, $versions).TrimEnd()
}

# NVD's known affected software configurations, laid out like the NVD page. A
# plain configuration lists vulnerable products; an AND configuration is only
# vulnerable in combination, e.g. firmware running on certain hardware, and its
# non-vulnerable parts are shown as 'running on/with'.
function Get-ConfigurationLines($Cve) {
	$lines = @()
	$number = 0

	foreach ($configuration in @($Cve.configurations)) {
		$number++
		$heading = "    Configuration $number"
		if ($configuration.operator -eq 'AND') {
			$heading += ' (vulnerable only in this combination)'
		}
		$lines += $heading

		foreach ($node in @($configuration.nodes)) {
			$prefix = if ($node.negate) { 'not ' } else { '' }
			foreach ($match in @($node.cpeMatch)) {
				if ($match.vulnerable) {
					$lines += "        $prefix$(Format-CpeMatch $match)"
				} else {
					$lines += "        running on/with: $prefix$(Format-CpeMatch $match)"
				}
			}
		}
	}

	return $lines
}

# Every vulnerable product and version range in NVD's configurations, as one
# line of text for the objects (and so for Export-Csv).
function Get-AffectedConfigurationText($Cve) {
	$entries = foreach ($configuration in @($Cve.configurations)) {
		foreach ($node in @($configuration.nodes)) {
			foreach ($match in @($node.cpeMatch | Where-Object vulnerable)) {
				(Format-CpeMatch $match) -replace '\s{2,}', ' '
			}
		}
	}
	return (@($entries | Select-Object -Unique) -join '; ')
}

# Fetches the CVE's record from CVE.org. Affected products are a nice-to-have on
# top of NVD's data, so $null is returned when CVE.org cannot be reached.
function Get-CveOrgRecord($Id) {
	try {
		Write-Verbose "CVE.org request: $CVEORG_URI/$Id"
		return Invoke-RestMethod -Uri "$CVEORG_URI/$Id" -Method Get -ErrorAction Stop
	} catch {
		Write-Host "Could not get $Id from CVE.org: $($_.Exception.Message)" -ForegroundColor Yellow
		return $null
	}
}

# 'affected: before 2.16.0' from one CVE.org version entry. A starting version
# of 0 or * means from the first version, so it is left out.
function Format-CveOrgVersion($Version) {
	$text = "$($Version.status):"
	$hasRange = $Version.lessThan -or $Version.lessThanOrEqual
	if (-not ($hasRange -and $Version.version -in @('0', '*'))) {
		$text += " $($Version.version)"
	}
	if ($Version.lessThan) {
		$text += " before $($Version.lessThan)"
	}
	if ($Version.lessThanOrEqual) {
		$text += " up to and including $($Version.lessThanOrEqual)"
	}
	return $text
}

# 'Apache Software Foundation - Apache Log4j' for a CVE.org affected product;
# older records use 'n/a' for both, which is left out.
function Format-CveOrgProductName($Product) {
	$name = @($Product.vendor, $Product.product | Where-Object { $_ -and $_ -ne 'n/a' }) -join ' - '
	if (-not $name) {
		return '(product not named)'
	}
	return $name
}

# One block per affected product in a CVE.org record: the product, then each
# version range and whether it is affected.
function Get-CveOrgAffectedLines($Record) {
	$lines = @()
	foreach ($product in @($Record.containers.cna.affected)) {
		$lines += "    $(Format-CveOrgProductName $product)"
		$versions = @($product.versions | Where-Object { $_ } | ForEach-Object { Format-CveOrgVersion $_ })
		if ($versions) {
			$versions | ForEach-Object { $lines += "        $_" }
		} elseif ($product.defaultStatus) {
			$lines += "        $($product.defaultStatus): all versions"
		}
	}
	return $lines
}

# The affected products as one line of text for the objects.
function Get-CveOrgAffectedText($Record) {
	$entries = foreach ($product in @($Record.containers.cna.affected)) {
		$versions = @($product.versions | Where-Object { $_ } | ForEach-Object { Format-CveOrgVersion $_ })
		"$(Format-CveOrgProductName $product) ($($versions -join ', '))"
	}
	return (@($entries) -join '; ')
}

# NVD names some sources (of CWEs and references) by their CVE.org organization
# ID rather than an e-mail address. The CVE.org record names the CNA and any
# ADPs (such as CISA-ADP, which adds data to records), so those IDs can be
# shown by name. Returns an ID-to-name table; empty without a record.
function Get-OrganizationNames($Record) {
	$organizations = @{}
	foreach ($container in @($Record.containers.cna) + @($Record.containers.adp)) {
		if ($container.providerMetadata.orgId) {
			$organizations[$container.providerMetadata.orgId] = $container.providerMetadata.shortName
		}
	}
	return $organizations
}

# A source's name when the organization table has one, otherwise the source as given.
function Format-Source($Source, $Organizations) {
	if ($Organizations -and $Organizations[$Source]) {
		return $Organizations[$Source]
	}
	return $Source
}

# Every reference as 'url [tags] (source)', as one line of text for the objects.
function Get-ReferenceText($Cve, $Organizations) {
	$entries = foreach ($reference in @($Cve.references)) {
		$text = $reference.url
		if ($reference.tags) {
			$text += " [$($reference.tags -join ', ')]"
		}
		"$text ($(Format-Source $reference.source $Organizations))"
	}
	return (@($entries) -join '; ')
}

# Keeps a long list to MAX_AFFECTED_LINES, saying how much was left out.
function Limit-Lines($Lines, $Url) {
	$all = @($Lines)
	if ($all.Count -le $MAX_AFFECTED_LINES) {
		return $all
	}
	return @($all | Select-Object -First $MAX_AFFECTED_LINES) +
		"    ... $($all.Count - $MAX_AFFECTED_LINES) more lines. Full list: -PassThru, or $Url"
}

# Prints one CVE in full: its scores and KEV status, the description, the
# weaknesses (CWE) with who assigned them, NVD's known affected software
# configurations, the affected products from CVE.org, and patch links.
function Show-CveDetails($Row, $Cve, $Record, $CweNames) {
	Write-Host ""
	$titleColor = if ($Row.'KEV Added') { 'Red' } else { 'Green' }
	Write-Host "=== $($Row.'CVE ID') ===" -ForegroundColor $titleColor
	Write-Host "Status: $($Row.Status)    Published: $($Row.Published)    Last modified: $($Row.'Last Modified')"

	$scoreLine = if ($null -ne $Row.Score) {
		"Severity: $($Row.Severity) $('{0:0.0}' -f $Row.Score) (CVSS $($Row.'CVSS Version'))"
	} else {
		"Severity: not scored yet"
	}
	if ($null -ne $Row.EPSS) {
		$scoreLine += "    EPSS: $(Format-Epss $Row.EPSS)"
	}
	Write-Host $scoreLine

	if ($Row.'KEV Added') {
		Write-Host "Known exploited: added to CISA KEV $($Row.'KEV Added'), due $($Row.'KEV Due')" -ForegroundColor Red
		if ($Row.'KEV Action') {
			Write-Host (Format-Wrapped "Required action: $($Row.'KEV Action')" 0)
		}
	}
	Write-Host $Row.URL

	Write-DetailSection 'Description' @(Format-Wrapped $Row.Description 4)

	# Placeholders NVD uses instead of a CWE, given their meaning.
	$placeholders = @{ 'NVD-CWE-noinfo' = 'Insufficient information'; 'NVD-CWE-Other' = 'Other (no fitting CWE)' }
	$organizations = Get-OrganizationNames $Record

	# NVD and the vendor often assign the same CWE, so each CWE is listed once
	# with everyone who assigned it.
	$assignments = @(foreach ($weakness in @($Cve.weaknesses)) {
		foreach ($description in @($weakness.description)) {
			[PSCustomObject]@{ Id = $description.value; Type = $weakness.type; Source = (Format-Source $weakness.source $organizations) }
		}
	})
	$weaknessLines = @($assignments | Group-Object Id | ForEach-Object {
		$name = if ($CweNames[$_.Name]) { $CweNames[$_.Name] } else { $placeholders[$_.Name] }
		"    {0,-16}{1}" -f $_.Name, $name
		$_.Group | ForEach-Object { "    {0,-16}{1}, assigned by {2}" -f '', $_.Type, $_.Source }
	})
	if (-not $weaknessLines) {
		$weaknessLines = @('    (none assigned yet)')
	}
	Write-DetailSection 'Weaknesses (CWE)' $weaknessLines

	$configurationLines = @(Get-ConfigurationLines $Cve)
	if (-not $configurationLines) {
		$configurationLines = @("    (none listed by NVD - status: $($Row.Status))")
	}
	Write-DetailSection 'Known affected software configurations (NVD)' (Limit-Lines $configurationLines $Row.URL)

	if ($Record) {
		$reporter = $Record.containers.cna.providerMetadata.shortName
		$productLines = @(Get-CveOrgAffectedLines $Record)
		if (-not $productLines) {
			$productLines = @('    (none listed)')
		}
		Write-DetailSection "Affected products (CVE.org, reported by $reporter)" (Limit-Lines $productLines "https://www.cve.org/CVERecord?id=$($Row.'CVE ID')")
	} else {
		Write-DetailSection 'Affected products (CVE.org)' @('    (CVE.org could not be reached)')
	}

	# As on the NVD page; patches are the references tagged 'Patch'.
	$references = @($Cve.references)
	$referenceLines = @($references | Select-Object -First $MAX_REFERENCES | ForEach-Object {
		$tags = if ($_.tags) { $_.tags -join ', ' } else { '(no tags)' }
		"    $($_.url)"
		"        Source: $(Format-Source $_.source $organizations)    Tags: $tags"
	})
	if ($references.Count -gt $MAX_REFERENCES) {
		$referenceLines += "    ... $($references.Count - $MAX_REFERENCES) more. Full list: -PassThru, or $($Row.URL)"
	}
	if (-not $referenceLines) {
		$referenceLines = @('    (none listed)')
	}
	Write-DetailSection "References To Advisories, Solutions & Tools ($($references.Count))" $referenceLines

	Write-Host ""
}

# Widens a cell so its column keeps a clear gap from the next one. Format-Table
# sizes each column to its widest cell, so padding the cells past the heading
# and adding the gutter is what opens the spacing up.
function Format-TableCell($Value, $Heading) {
	$gutter = ' ' * $COLUMN_GUTTER
	return ("$Value" + $gutter).PadRight($Heading.Length + $COLUMN_GUTTER)
}

# Renders one section of the results as a plain-text table. The KEV columns
# are only shown in the known-exploited section, where they are filled in.
# Patch links are too long for a table column and follow it as a list instead.
function Format-ResultsTable($Rows, $IncludeKev) {
	if (-not $Rows) {
		return "    (none)"
	}

	$columns = @(
		@{ Name = 'CVE ID';    Expression = { Format-TableCell $_.'CVE ID' 'CVE ID' } },
		@{ Name = 'Published'; Expression = { Format-TableCell $_.'Published' 'Published' } },
		@{ Name = 'Severity';  Expression = { Format-TableCell $_.'Severity' 'Severity' } },
		@{ Name = 'Score';     Expression = { Format-TableCell ('{0:0.0}' -f $_.'Score') 'Score' } },
		@{ Name = 'EPSS';      Expression = { Format-TableCell (Format-Epss $_.'EPSS') 'EPSS' } },
		@{ Name = 'CWE';       Expression = { Format-TableCell $_.'CWE' 'CWE' } }
	)

	if ($IncludeKev) {
		$columns += @{ Name = 'KEV Added'; Expression = { Format-TableCell $_.'KEV Added' 'KEV Added' } }
		$columns += @{ Name = 'KEV Due';   Expression = { Format-TableCell $_.'KEV Due' 'KEV Due' } }
	}

	$lines = @(($Rows | Format-Table $columns -AutoSize | Out-String -Width 500).Trim())

	$patched = @($Rows | Where-Object { $_.'Patch Links' })
	if ($patched) {
		$lines += ""
		$lines += "Patch links:"
		foreach ($row in $patched) {
			$label = $row.'CVE ID'
			foreach ($link in ($row.'Patch Links' -split ' ')) {
				$lines += "    {0,-18}{1}" -f $label, $link
				$label = ''
			}
		}
	}

	return ($lines -join [Environment]::NewLine)
}

# Prints the search results to the terminal. Known exploited CVEs come first,
# since those are the ones to patch first; the rest follow grouped by severity.
# Within a severity, the CVEs most likely to be exploited (EPSS) come first,
# then the highest CVSS score. Empty severity sections are left out. The CWEs
# follow: counted with -CweSummary, otherwise as a list of their names.
function Show-CveResults($Rows, $SearchDescription, $CweNames) {
	$rowList = @($Rows)

	$exploited = @($rowList | Where-Object { $_.'KEV Added' } | Sort-Object 'KEV Due', 'CVE ID')
	$others = @($rowList | Where-Object { -not $_.'KEV Added' })

	$likelihoodOrder = @(
		@{ Expression = { if ($null -eq $_.EPSS) { -1 } else { $_.EPSS } }; Descending = $true },
		@{ Expression = 'Score'; Descending = $true }
	)

	$sections = [ordered]@{}
	foreach ($level in @('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')) {
		$sections[$level] = @($others | Where-Object { $_.Severity -eq $level } | Sort-Object $likelihoodOrder)
	}
	$sections['UNSCORED'] = @($others | Where-Object { $_.Severity -notin @('CRITICAL', 'HIGH', 'MEDIUM', 'LOW') } | Sort-Object $likelihoodOrder)

	Write-Host ""
	Write-Host "NVD Vulnerability Search"
	Write-Host "Search:  $SearchDescription"
	Write-Host "Summary: $($rowList.Count) found, $($exploited.Count) known exploited, $(@($rowList | Where-Object Severity -eq 'CRITICAL').Count) critical, $(@($rowList | Where-Object Severity -eq 'HIGH').Count) high"
	Write-Host ""

	Write-Host "=== Known exploited - CISA KEV ($($exploited.Count)) ===" -ForegroundColor Red
	Write-Host (Format-ResultsTable $exploited $true)
	Write-Host ""

	# -KevOnly asks for the KEV table alone: the severity sections and the CWE
	# list are left out. -CweSummary is still shown, since it was asked for too.
	if (-not $KevOnly) {
		foreach ($section in $sections.GetEnumerator()) {
			if (-not $section.Value) {
				continue
			}
			Write-Host "=== $($section.Key) ($($section.Value.Count)) ===" -ForegroundColor Cyan
			Write-Host (Format-ResultsTable $section.Value $false)
			Write-Host ""
		}
	}

	if ($CweSummary) {
		Write-Host "=== Weaknesses (CWE) by number of CVEs ===" -ForegroundColor Cyan
		Write-Host (Format-CweSummary $rowList $CweNames)
		Write-Host ""
	} elseif (-not $KevOnly) {
		Write-Host "=== Weaknesses (CWE) ===" -ForegroundColor Cyan
		Write-Host (Format-CweList $rowList $CweNames)
		Write-Host ""
	}
}

# --- Describe one CWE from MITRE's catalog; NVD is not needed ---
if ($resolvedCweInfo) {
	Show-CweInfo $resolvedCweInfo
	return
}

# --- Resolve -Product to a CPE through the NVD CPE dictionary ---
$cpeFilter = $Cpe
if ($Product) {
	try {
		$cpeFilter = Resolve-ProductCpe $Product
	} catch {
		Write-Host "Failed to query the NVD CPE API: $($_.Exception.Message)" -ForegroundColor Red
		return
	}

	if (-not $cpeFilter) {
		return
	}

	Write-Host "Product '$Product' resolved to $cpeFilter" -ForegroundColor DarkGray
	Start-Sleep -Seconds $REQUEST_DELAY_SECONDS
}

# --- Query the NVD CVE API ---
try {
	if ($resolvedIds) {
		$results = @(Get-CvesById $resolvedIds)
	} else {
		$results = @(Search-Cves (Get-SearchQuery $cpeFilter))
	}
} catch {
	Write-Host "Failed to query the NVD CVE API: $($_.Exception.Message)" -ForegroundColor Red
	return
}

# --- Add EPSS exploit likelihood from FIRST, and CWE names from MITRE ---
$cweNames = @{}
if ($results) {
	Add-EpssScores $results
	$cweNames = Get-CweNames
	Add-CweNames $results $cweNames
}

# --- CVEs looked up by ID: add the affected products from CVE.org ---
$cveOrgRecords = @{}
foreach ($row in @($results | Where-Object { $resolvedIds })) {
	$record = Get-CveOrgRecord $row.'CVE ID'
	$cveOrgRecords[$row.'CVE ID'] = $record
	if ($record) {
		$row.'Affected Products' = Get-CveOrgAffectedText $record
		$row.References = Get-ReferenceText $script:RawCves[$row.'CVE ID'] (Get-OrganizationNames $record)
	}
}

# --- CVEs looked up by ID: show each in detail, or send the objects down the
#     pipeline when the output is piped on (| Export-Csv) or -PassThru is given ---
# --- CVEs found by a search: print them grouped by severity ---
if ($resolvedIds) {
	# Piped means a command follows the script on the line that ran it. 'pwsh
	# -File', as Task Scheduler runs it, reports a pipeline too, but with an
	# empty line, so it still gets the detail view.
	$outputIsPiped = $MyInvocation.PipelinePosition -lt $MyInvocation.PipelineLength -and $MyInvocation.Line -match '\|'
	if ($PassThru -or $outputIsPiped) {
		$results
	} else {
		foreach ($row in $results) {
			Show-CveDetails -Row $row -Cve $script:RawCves[$row.'CVE ID'] -Record $cveOrgRecords[$row.'CVE ID'] -CweNames $cweNames
		}
	}
} else {
	Show-CveResults -Rows $results -SearchDescription (Format-SearchDescription $cpeFilter) -CweNames $cweNames
}
