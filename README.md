# MITRE ATT&CK Heatmap Generator

A Python tool that generates [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) heatmaps by aggregating techniques used by threat actor groups. Search for threat groups by keywords (e.g., industry verticals like "financial", "energy", "telecommunications") and automatically merge all their techniques into a single, scored heatmap layer.

## What's New: Refactored with mitreattack-python

This tool has been completely refactored to use the official [mitreattack-python](https://github.com/mitre-attack/mitreattack-python) library, providing:

- **Simplified codebase**: Single-file implementation using the official MITRE library
- **Automatic version detection**: ATT&CK and Navigator versions are detected automatically
- **Better reliability**: Uses official library methods with fallback mechanisms
- **Future-proof**: Leverages maintained MITRE infrastructure

## Features

- **Keyword-based threat group search**: Filter threat groups by searching their descriptions for specific terms (industry sectors, regions, etc.)
- **Automatic technique aggregation**: Merges techniques from all matching groups into a single heatmap
- **Score-based visualization**: Techniques are scored by how many groups use them, with gradient coloring (red → yellow → green)
- **Sub-technique support**: Optionally propagate sub-technique usage to parent techniques
- **Threshold filtering**: Filter out low-frequency techniques to focus on the most common attack patterns
- **Always up-to-date**: Downloads the latest MITRE ATT&CK STIX data directly from the official repository
- **Dynamic versioning**: Automatically detects ATT&CK version and Navigator version to avoid compatibility warnings

---

## Installation

### Prerequisites

- Python 3.9 or higher
- pip (Python package installer)
- Internet connection (to download ATT&CK data)

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/MITRE-ATTACK-heatmap-gen.git
   cd MITRE-ATTACK-heatmap-gen
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

   This will install:
   - `mitreattack-python>=5.0.0` - Official MITRE ATT&CK library
   - `requests` - HTTP client for data downloads

---

## Quick Start

Generate your first heatmap in seconds:

```bash
# Create a heatmap for the energy sector
python gen_heatmap.py -s energy -o energy_heatmap -t "Energy Sector Threats"
```

Then open the generated `energy_heatmap.json` file in [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).

---

## Usage Guide

### Basic Syntax

```bash
python gen_heatmap.py -s <search_terms> -o <output_filename> -t <tab_title>
```

### Command-Line Options Reference

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `-s, --search` | Yes | - | One or more search terms to filter threat groups. Use `'*'` for all groups |
| `-o, --outfile` | Yes | - | Output filename (without `.json` extension) |
| `-t, --title` | Yes | - | Tab title displayed in ATT&CK Navigator |
| `--merge-tech` | No | Enabled | Propagate sub-technique scores to parent techniques |
| `--no-merge-tech` | No | - | Disable parent technique score propagation |
| `--threshold N` | No | 0 | Filter out parent techniques with score below N |

---

## Practical Examples (HOWTO)

This section provides step-by-step examples for common use cases. Each example explains not just *how* to run the command, but *why* you might want to use it.

### Example 1: Energy Sector Heatmap

**Scenario**: You work for an energy company and want to understand which ATT&CK techniques are most commonly used by threat actors targeting your industry.

```bash
python gen_heatmap.py -s energy -o energy_sector -t "Energy Sector Threat Landscape"
```

**What this does**:
- Searches all threat group descriptions for the word "energy"
- Finds groups like APT33, OilRig, and others known to target energy
- Aggregates all techniques used by these groups
- Creates `energy_sector.json` ready for Navigator import

**Sample output**:
```
[+] Downloading latest version of MITRE ATT&CK
[+] Detecting version info
[-] ATT&CK version: 17.1
[-] Navigator version: 5.2.0
[-] Layer format: 4.5
[+] Loading ATT&CK data
[+] The following verticals have been selected:
[-] Energy
[+] The following groups have been identified targeting: energy
[-] OilRig
[-] APT33
[-] HEXANE
...
[+] Merging techniques from 9 different groups.
[+] Building Navigator layer
[+] Processing done! Output saved to /path/to/energy_sector.json
```

---

### Example 2: Retail and E-commerce Heatmap

**Scenario**: You're a security analyst for a retail company and need to assess threats targeting retail and financial transaction systems.

```bash
python gen_heatmap.py -s retail financial "point of sale" -o retail_threats -t "Retail & Financial Threats"
```

**What this does**:
- Searches for groups mentioning "retail", "financial", OR "point of sale"
- Combines all matching groups into a single comprehensive heatmap
- Useful for industries with overlapping threat profiles

**Why multiple search terms?**: Threat actors often target multiple related industries. A group targeting "financial" institutions might also attack retail payment systems.

---

### Example 3: Telecommunications Sector

**Scenario**: You manage security for a telecom provider and want to prioritize defenses against known telecom-targeting adversaries.

```bash
python gen_heatmap.py -s telecommunications telecom -o telco_heatmap -t "Telecommunications Threats"
```

**Pro tip**: Use multiple variations of industry terms (e.g., "telecommunications" and "telecom") to catch all relevant groups.

---

### Example 4: Using the Wildcard (*) - All Threat Groups

**Scenario**: You want a comprehensive view of ALL techniques used by ALL known threat groups, regardless of their targeting.

```bash
python gen_heatmap.py -s '*' -o all_groups -t "All Known Threat Groups"
```

**What this does**:
- Includes every non-deprecated, non-revoked threat group in MITRE ATT&CK
- Shows the complete landscape of adversary techniques
- Scores indicate how many groups (out of 100+) use each technique

**When to use the wildcard**:
- Creating a baseline threat landscape
- Identifying the most commonly used techniques across all adversaries
- Building generic detection strategies
- Training and educational purposes

**Caution**: This produces a very "hot" heatmap since popular techniques will have high scores. Consider using `--threshold` to filter noise.

---

### Example 5: Using Threshold Filtering

**Scenario**: You ran the wildcard search but the heatmap is overwhelming. You only want to focus on techniques used by many groups.

```bash
python gen_heatmap.py -s '*' -o common_techniques -t "Techniques Used by 10+ Groups" --threshold 10
```

**What threshold does**:
- Removes parent techniques with score < 10 from the output
- Sub-techniques are ALWAYS kept (regardless of threshold) to maintain context
- Helps focus on the most prevalent attack patterns

**Example use cases for different thresholds**:

| Threshold | Use Case |
|-----------|----------|
| `--threshold 3` | Filter noise, keep moderately common techniques |
| `--threshold 5` | Focus on well-established attack patterns |
| `--threshold 10` | Show only the most widespread techniques |
| `--threshold 20` | Identify "universal" techniques nearly all groups use |

**Combined example** - Energy sector, only common techniques:
```bash
python gen_heatmap.py -s energy -o energy_common -t "Energy - Common Techniques (3+)" --threshold 3
```

---

### Example 6: Disabling Parent Technique Merging

**Scenario**: You want to see exactly which techniques (including sub-techniques) are documented, without inflating parent technique scores.

```bash
python gen_heatmap.py -s financial -o financial_exact -t "Financial - Exact Matches Only" --no-merge-tech
```

**Understanding merge-tech (default: enabled)**:

When a threat group uses sub-technique `T1059.001` (PowerShell):
- **With `--merge-tech` (default)**: Both `T1059` (Command and Scripting Interpreter) AND `T1059.001` (PowerShell) get +1 score
- **With `--no-merge-tech`**: Only `T1059.001` (PowerShell) gets +1 score

**When to disable merging**:
- You want precise sub-technique attribution
- You're analyzing technique specificity
- Parent technique scores seem artificially inflated

**When to keep merging enabled** (default):
- You want a holistic view of technique categories
- You're building detection at the parent technique level
- You want to ensure parent techniques reflect sub-technique activity

---

### Example 7: Geographic Targeting

**Scenario**: You want to understand threats targeting specific regions.

```bash
# Middle East targeting
python gen_heatmap.py -s "Middle East" -o middle_east -t "Middle East Targeting Groups"

# Asia-Pacific region
python gen_heatmap.py -s asia pacific japan korea china -o apac -t "APAC Threat Landscape"

# European focus
python gen_heatmap.py -s europe european ukraine russia -o europe -t "European Threats"
```

---

### Example 8: Healthcare Sector with Filtered Results

**Scenario**: Healthcare CISO needs a focused view of common attack techniques against the industry.

```bash
python gen_heatmap.py -s healthcare medical hospital pharmaceutical -o healthcare_focused -t "Healthcare - Priority Techniques" --threshold 2
```

**This combination**:
1. Casts a wide net with multiple healthcare-related terms
2. Aggregates techniques from all matching groups
3. Filters to show only techniques used by 2+ groups
4. Results in an actionable, prioritized heatmap

---

## Output and Visualization

### Generated Files

The tool creates a single JSON file (e.g., `energy_sector.json`) compatible with ATT&CK Navigator.

### Viewing Your Heatmap

1. Go to [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
2. Click **"Open Existing Layer"**
3. Select **"Upload from Local"**
4. Choose your generated `.json` file

### Understanding the Visualization

| Element | Meaning |
|---------|---------|
| **Score** | Number of threat groups using that technique |
| **Red cells** | Lower scores (fewer groups use this technique) |
| **Yellow cells** | Medium scores |
| **Green cells** | Higher scores (many groups use this technique) |
| **Empty cells** | Technique not used by any matching groups |

### Pro Tips for Navigator

- **Hover over techniques** to see the score in the tooltip
- **Use the search** to find specific technique IDs
- **Export as SVG/PNG** for reports and presentations
- **Layer multiple heatmaps** to compare sectors

---

## How It Works

### Architecture

The tool uses the official `mitreattack-python` library for all ATT&CK data operations:

```
┌─────────────────────────────────────────────────────────────────┐
│                        gen_heatmap.py                           │
├─────────────────────────────────────────────────────────────────┤
│  1. Download STIX data (mitreattack-python / direct fallback)   │
│  2. Detect versions (release_info.get_attack_version)           │
│  3. Load data (MitreAttackData)                                 │
│  4. Search groups (get_objects_by_content)                      │
│  5. Get techniques (get_all_techniques_used_by_all_groups)      │
│  6. Build layer (navlayers.Layer, Technique, Gradient)          │
│  7. Save JSON output                                            │
└─────────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Download**: Fetches latest STIX 2.1 data from [mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data)
2. **Version Detection**: Uses hash-based detection for ATT&CK version; GitHub API for Navigator version
3. **Group Search**: Searches `description` field of intrusion-set objects (case-insensitive)
4. **Technique Extraction**: Follows STIX relationships from groups to techniques
5. **Aggregation**: Counts technique occurrences across all matching groups
6. **Layer Generation**: Uses `navlayers` module to create Navigator-compatible JSON

---

## Project Structure

```
MITRE-ATTACK-heatmap-gen/
├── gen_heatmap.py      # Main script (single-file implementation)
├── requirements.txt    # Python dependencies
└── README.md           # This documentation
```

---

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `mitreattack-python` | >=5.0.0 | Official MITRE ATT&CK library for STIX data access, relationship queries, and Navigator layer generation |
| `requests` | latest | HTTP client for downloading STIX data and fetching version info |

---

## Version Information

The tool automatically detects and applies the correct versions:

| Component | Detection Method |
|-----------|------------------|
| **ATT&CK Version** | Hash-based detection from downloaded STIX file |
| **Navigator Version** | GitHub Releases API query |
| **Layer Format** | Fixed at 4.5 (enforced by mitreattack-python) |

This ensures your generated layers are always compatible with the latest ATT&CK Navigator.

---

## Troubleshooting

### "Library download failed, falling back to direct download"

This is **normal behavior**. The tool attempts to use the library's download function first, then falls back to direct GitHub download if needed. Both methods work correctly.

### Network Issues

If downloads fail completely:
- Check your internet connection
- Verify access to `raw.githubusercontent.com`
- Check if you're behind a proxy (configure `HTTP_PROXY`/`HTTPS_PROXY` environment variables)
- The initial download is ~25MB of STIX data

### No Groups Found

If your search returns no groups:
```
[+] The following groups have been identified targeting: obscure_term
(no groups listed)
```

**Solutions**:
- Try broader search terms
- Check spelling
- Use `'*'` to see all available groups and their descriptions
- Remember: search is case-insensitive

### Empty Heatmap (No Techniques)

If the output has no colored cells:
- Verify that matching groups were found (check console output)
- Lower or remove the `--threshold` value
- Some groups may have limited technique documentation

### Version Warnings in Navigator

If Navigator shows version warnings:
- The tool should auto-detect correct versions
- If issues persist, it's likely a temporary mismatch with latest Navigator release
- The heatmap will still function correctly

---

## Use Cases

| Use Case | Recommended Approach |
|----------|---------------------|
| **Industry threat assessment** | `-s <industry_keywords> --threshold 2` |
| **Baseline threat landscape** | `-s '*' --threshold 10` |
| **Specific adversary focus** | Search for group names or aliases |
| **Purple team planning** | `-s <your_industry>` to prioritize test cases |
| **Executive reporting** | Use Navigator's export to SVG/PNG |
| **Detection engineering** | Focus on high-score techniques first |
| **Gap analysis** | Compare heatmap against your detection coverage |

---

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

### Development Notes

- Single-file design for simplicity
- All functions have Google-style docstrings
- Type hints throughout for IDE support
- Follows PEP 8 conventions

---

## License

This project is provided as-is for security research and defensive purposes.

---

## Acknowledgments

- [MITRE ATT&CK](https://attack.mitre.org/) - The threat intelligence framework
- [mitreattack-python](https://github.com/mitre-attack/mitreattack-python) - Official Python library
- [ATT&CK Navigator](https://github.com/mitre-attack/attack-navigator) - Visualization tool
- [MITRE ATT&CK STIX Data](https://github.com/mitre-attack/attack-stix-data) - Machine-readable ATT&CK data
