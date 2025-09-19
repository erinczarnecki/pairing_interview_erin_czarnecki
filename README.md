# CVE Analysis Tool - Engineering Interview

## Overview
Build a tool to analyze CVE data and identify the most critical security vulnerabilities based on their CVSS scores.

### Background
- **CVE (Common Vulnerabilities and Exposures)**: Standardized identifiers for known security vulnerabilities (e.g., CVE-2024-1234)
- **CVSS (Common Vulnerability Scoring System)**: A framework for rating the severity of vulnerabilities on a scale of 0-10.

## Stage 1: Parse and Rank CVEs

**Input:** `cves.csv` - CVE identifiers with CVSS v1 vector strings

### Tasks
- Parse CSV and extract CVE IDs with their CVSS vectors
- Calculate base score for each CVE using the appropriate formula
- Display top 5 CVEs by severity (highest score first)

### Expected Output
```
Top 5 CVEs by Severity:
1. CVE-2024-1234 - Score: 9.8
2. CVE-2023-5678 - Score: 9.5
3. CVE-2024-9012 - Score: 8.7
...
```

### CVSS v1 Scoring

CVSS v1 vectors contain three components separated by slashes:
- **AV (Access Vector)**: How the attack is delivered
  - N = Network (remotely exploitable)
  - L = Local (requires local system access)
  - P = Physical (requires physical access)
- **AC (Access Complexity)**: How difficult the attack is
  - L = Low (easy to exploit)
  - H = High (difficult conditions required)
- **I (Impact)**: The damage caused
  - C = Complete (total system compromise)
  - H = High (significant damage)
  - L = Low (limited damage)

```ruby
CVSS_V1_SCORES = {
  'AV' => { 'N' => 1.0, 'L' => 0.65, 'P' => 0.4 },
  'AC' => { 'L' => 0.8, 'H' => 0.6 },
  'I' => { 'C' => 1.0, 'H' => 0.75, 'L' => 0.5 }
}

# Formula: Base Score = 10 * AV * AC * I
```

**Example:**
Vector: `CVSS:1/AV:N/AC:L/I:C`
- AV:N = 1.0
- AC:L = 0.8
- I:C = 1.0
- Score = 10 * 1.0 * 0.8 * 1.0 = 8.0

## Stage 2: CVSS v2 Scoring

**Input:** `cves2.csv` - CVE identifiers with CVSS vector strings (mix of v1 and v2 formats)

### Tasks
- Parse CSV containing a mix of v1 and v2 vectors
- Calculate base score for each CVE using the appropriate formula
- Display top 5 CVEs by severity (highest score first)

### Expected Output
```
Top 5 CVEs by Severity:
1. CVE-2024-1234 - Score: 9.8 (CVSS v2)
2. CVE-2023-5678 - Score: 9.5 (CVSS v1)
3. CVE-2024-9012 - Score: 8.7 (CVSS v2)
...
```

CVSS v2 adds a fourth component for authentication:
- **AV (Access Vector)**: Same as v1 but adds:
  - A = Adjacent Network (same network segment)
- **AC (Access Complexity)**: Same as v1 but adds:
  - M = Medium (some special conditions)
- **Au (Authentication)**: Authentication needed to exploit
  - N = None (no authentication)
  - S = Single (one login required)
  - M = Multiple (multiple logins required)
- **I (Impact)**: Same as v1

```ruby
CVSS_V2_SCORES = {
  'AV' => { 'N' => 1.0, 'A' => 0.646, 'L' => 0.395, 'P' => 0.2 },
  'AC' => { 'L' => 0.71, 'M' => 0.61, 'H' => 0.35 },
  'Au' => { 'N' => 0.704, 'S' => 0.56, 'M' => 0.45 },
  'I' => { 'C' => 1.0, 'H' => 0.75, 'L' => 0.5 }
}

# Formula: Base Score = 10 * AV * AC * Au * I
```

**Example:**
Vector: `CVSS:2/AV:N/AC:L/Au:N/I:C`
- AV:N = 1.0
- AC:L = 0.71
- Au:N = 0.704
- I:C = 1.0
- Score = 10 * 1.0 * 0.71 * 0.704 * 1.0 = 5.0

## Stage 3: Custom Scoring & Prioritization

**Input:** `org_weights.csv` - Per-organization weights for CVSS components (0.0 to 1.0)

### Tasks
- Load organization weights from CSV
- Calculate custom scores for each CVE using org-specific weights
- Generate top 5 CVEs per organization

### Expected Output
```
org-1:
1. CVE-2024-1234 - Score: 8.0
2. CVE-2023-5678 - Score: 7.5
...

org-2:
1. CVE-2023-9999 - Score: 12.3
2. CVE-2024-1234 - Score: 11.2
...
```

### Weighted Scoring

Organizations express how much they care about each component using weights from 0 to 1:
- **Weight = 1.0**: Full impact (use original CVSS coefficient)
- **Weight = 0.0**: No impact (neutralize this factor by setting coefficient to 1.0)
- **Weight = 0.5**: Half impact (move coefficient halfway toward 1.0)

**Adjustment Formula:**
```
adjusted_coefficient = 1 - weight * (1 - original_coefficient)
```

**Example:** If AV coefficient is 0.4 and org weight is 0.5:
```
adjusted = 1 - 0.5 * (1 - 0.4) = 1 - 0.5 * 0.6 = 0.7
```

**CVSS v1 Weighted Score:**
```
Org Score = 10 * adjusted_AV * adjusted_AC * adjusted_I
```

**CVSS v2 Weighted Score:**
```
Org Score = 10 * adjusted_AV * adjusted_AC * adjusted_Au * adjusted_I
```

*Note: For v1 vectors, Au weight is ignored (no Authentication component)*

## Stage 4: Vulnerabilities and Advisories

**Inputs:**
- `advisories.csv` - Security advisories mapping CVEs to affected packages/versions and available fixes
- `inventory.csv` - Organization package inventories with current versions

### Tasks
- Identify which CVEs affect each organization based on their installed packages
- Determine if patches are available
- Display top 5 vulnerable CVEs per org (sorted by org-specific score from Stage 2)

### Expected Output
```
org-1 Vulnerabilities:
1. CVE-2024-1234 (nginx 1.21.0) - Score: 8.5 - Patch available: 1.22.2
2. CVE-2023-5678 (redis 2.4.1) - Score: 7.2 - No patch available
...

org-2 Vulnerabilities:
1. CVE-2023-9999 (openssl 3.0.1) - Score: 9.1 - No patch available
...
```

### Version Range Formats
Support these semver patterns:
- **Range:** `1.2.0-1.2.5` (versions 1.2.0 through 1.2.5 inclusive)
- **Comparison:** `>=1.9.0 <1.9.15` (1.9.0 or higher, but less than 1.9.15)
- **Wildcard:** `2.x` or `1.5.x` (any patch/minor version)