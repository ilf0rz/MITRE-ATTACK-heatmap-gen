#!/usr/bin/env python3
"""
MITRE ATT&CK Navigator Heatmap Generator

Generates ATT&CK Navigator heatmaps by aggregating techniques used by threat actor
groups. Searches threat group descriptions for keywords and merges all techniques
used by matching groups into a single heatmap layer.
"""

import os
import argparse
import shutil
import tempfile
from typing import Any

import requests

from mitreattack import download_stix, release_info
from mitreattack.stix20 import MitreAttackData
from mitreattack.navlayers import Layer, Technique, Gradient, Versions

# Type alias for STIX objects (library doesn't export proper types)
StixObject = Any

NAVIGATOR_RELEASES_URL = "https://api.github.com/repos/mitre-attack/attack-navigator/releases/latest"
DOMAIN = "enterprise-attack"

# Layer version is enforced by mitreattack-python library (force-upgrades to 4.5)
LAYER_VERSION = "4.5"

# Gradient colors for heatmap: red (low) -> yellow (medium) -> green (high)
GRADIENT_COLORS = ["#ff6666ff", "#ffe766ff", "#8ec843ff"]


def get_attack_version(stix_file: str) -> str:
    """Get ATT&CK version from the downloaded STIX file using the library.

    Args:
        stix_file: Path to the downloaded STIX JSON file.

    Returns:
        ATT&CK version string (e.g., '14.1'). Falls back to library's
        LATEST_VERSION if version cannot be detected.
    """
    version = release_info.get_attack_version(
        domain=DOMAIN,
        stix_version="2.1",
        stix_file=stix_file
    )
    if version:
        return version

    # Fallback: try STIX 2.0 format
    version = release_info.get_attack_version(
        domain=DOMAIN,
        stix_version="2.0",
        stix_file=stix_file
    )
    if version:
        return version

    # Ultimate fallback to library's latest known version
    return release_info.LATEST_VERSION


def get_latest_navigator_version() -> str:
    """Fetch the latest ATT&CK Navigator version from GitHub releases.

    Returns:
        Navigator version string (e.g., '5.1.0'). Falls back to '5.0.0'
        if the GitHub API is unreachable.
    """
    try:
        response = requests.get(NAVIGATOR_RELEASES_URL, timeout=30)
        response.raise_for_status()
        release = response.json()

        # tag_name is typically "vX.Y.Z", strip the leading 'v'
        tag = release.get("tag_name", "v5.0.0")
        return tag.lstrip("v")
    except requests.RequestException:
        return "5.0.0"  # Fallback if unable to fetch


def download_stix_data() -> str:
    """Download ATT&CK STIX data using the library and return the file path.

    Returns:
        Path to the downloaded STIX JSON file in a temporary directory.

    Raises:
        SystemExit: If both library and direct download methods fail.
    """
    print('[+] Downloading latest version of MITRE ATT&CK')

    # Create a temp directory for the download
    download_dir = tempfile.mkdtemp(prefix="attack_stix_")

    try:
        # Use the library's download function
        # Downloads latest version by default
        download_stix.download_domains(
            domains=[DOMAIN],
            download_dir=download_dir,
            all_versions=False,
            stix_version="2.1",
            attack_versions=None  # Latest
        )

        # Find the downloaded file
        for root, _, files in os.walk(download_dir):
            for filename in files:
                if filename.endswith('.json') and DOMAIN in filename:
                    return os.path.join(root, filename)

        raise FileNotFoundError("Downloaded STIX file not found")

    except (FileNotFoundError, OSError, ImportError, ValueError, AttributeError) as e:
        # Fallback to direct download if library method fails
        print(f'[!] Library download failed ({e}), falling back to direct download')
        return download_stix_direct(download_dir)


def download_stix_direct(download_dir: str) -> str:
    """Fallback: Download STIX data directly from GitHub.

    Args:
        download_dir: Directory path where the STIX file will be saved.

    Returns:
        Path to the downloaded STIX JSON file.

    Raises:
        SystemExit: If the download fails.
    """
    url = f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/{DOMAIN}/{DOMAIN}.json"

    try:
        response = requests.get(url, timeout=120)
        response.raise_for_status()

        file_path = os.path.join(download_dir, f"{DOMAIN}.json")
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(response.text)
        return file_path
    except requests.RequestException as e:
        raise SystemExit(f"[!] Failed to download ATT&CK data: {e}")


def positive_int(x: str) -> int:
    """Argparse type validator for positive integers.

    Args:
        x: String value to validate and convert.

    Returns:
        Positive integer value.

    Raises:
        argparse.ArgumentTypeError: If value is not a valid positive integer.
    """
    try:
        val = int(x)
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{x}' is not a valid integer")
    if val <= 0:
        raise argparse.ArgumentTypeError(f"{val} is not a positive integer")
    return val


def search_groups(mitre: MitreAttackData, search_terms: list[str]) -> list[StixObject]:
    """Search for groups matching the given search terms in their descriptions.

    Args:
        mitre: Loaded MitreAttackData instance.
        search_terms: List of keywords to search in group descriptions.
            Use '*' to match all groups.

    Returns:
        Deduplicated list of matching STIX intrusion-set objects.
    """
    groups = []

    for term in search_terms:
        if term == '*':
            # Get all non-revoked, non-deprecated groups
            all_groups = mitre.get_groups(remove_revoked_deprecated=True)
            groups.extend(all_groups)
        else:
            # Search in description (case-insensitive)
            matching = mitre.get_objects_by_content(
                term,
                object_type="intrusion-set",
                remove_revoked_deprecated=True
            )
            groups.extend(matching)

    # Deduplicate by STIX ID
    seen_ids = set()
    deduped = []
    for group in groups:
        if group.id not in seen_ids:
            seen_ids.add(group.id)
            deduped.append(group)

    return deduped


def aggregate_techniques(
    mitre: MitreAttackData,
    groups: list[StixObject],
    merge_tech: bool
) -> dict[tuple[str, str], int]:
    """Aggregate techniques used by the given groups.

    Args:
        mitre: Loaded MitreAttackData instance.
        groups: List of STIX intrusion-set objects to analyze.
        merge_tech: If True, increment parent technique score when
            a sub-technique is encountered.

    Returns:
        Dictionary mapping (tactic_name, technique_id) tuples to
        occurrence counts (scores).
    """
    # Get all group->technique relationships at once (more efficient)
    group_techniques = mitre.get_all_techniques_used_by_all_groups()

    technique_scores: dict[tuple[str, str], int] = {}

    for group in groups:
        if group.id not in group_techniques:
            continue

        for entry in group_techniques[group.id]:
            technique = entry["object"]

            # Get the ATT&CK ID (e.g., T1059.001)
            attack_id = mitre.get_attack_id(technique.id)
            if not attack_id:
                continue

            # Get tactics from kill chain phases
            if not hasattr(technique, 'kill_chain_phases') or not technique.kill_chain_phases:
                continue

            for phase in technique.kill_chain_phases:
                tactic_name = phase['phase_name']

                # List of technique IDs to increment
                tech_ids_to_process = [attack_id]

                # If merge_tech is enabled and this is a sub-technique, also increment parent
                if merge_tech and '.' in attack_id:
                    parent_id = attack_id.split('.')[0]
                    tech_ids_to_process.append(parent_id)

                for tech_id in tech_ids_to_process:
                    key = (tactic_name, tech_id)
                    technique_scores[key] = technique_scores.get(key, 0) + 1

    return technique_scores


def filter_by_threshold(
    technique_scores: dict[tuple[str, str], int],
    threshold: int
) -> dict[tuple[str, str], int]:
    """Filter out parent techniques below threshold.

    Args:
        technique_scores: Dictionary mapping (tactic, technique_id) to scores.
        threshold: Minimum score for parent techniques to be included.

    Returns:
        Filtered dictionary. Sub-techniques (containing '.') are always
        kept regardless of score.
    """
    if threshold == 0:
        return technique_scores

    return {
        (tactic, tech_id): score
        for (tactic, tech_id), score in technique_scores.items()
        if '.' in tech_id or score >= threshold
    }


def build_layer(
    name: str,
    technique_scores: dict[tuple[str, str], int],
    attack_version: str,
    navigator_version: str
) -> Layer:
    """Build a Navigator layer from aggregated technique scores.

    Args:
        name: Layer name and tab title for the Navigator.
        technique_scores: Dictionary mapping (tactic, technique_id) to scores.
        attack_version: ATT&CK framework version string.
        navigator_version: ATT&CK Navigator version string.

    Returns:
        Configured Layer object ready to be saved.
    """

    # Create layer with name and domain
    layer = Layer(name=name, domain=DOMAIN)
    layer.layer.description = f"Aggregated techniques for: {name}"

    # Set versions dynamically to avoid Navigator warnings
    layer.layer.versions = Versions(
        layer=LAYER_VERSION,
        attack=attack_version,
        navigator=navigator_version
    )

    # Calculate max score for gradient
    max_score = max(technique_scores.values()) if technique_scores else 1

    # Set up gradient
    layer.layer.gradient = Gradient(
        colors=GRADIENT_COLORS,
        minValue=1,
        maxValue=max_score
    )

    # Build techniques list
    techniques = []
    for (tactic, tech_id), score in technique_scores.items():
        tech = Technique(tech_id)
        tech.tactic = tactic
        tech.score = score
        techniques.append(tech)

    layer.layer.techniques = techniques

    return layer


def main():
    parser = argparse.ArgumentParser(
        description='Generates ATT&CK Navigator heatmap, merging multiple threat actors techniques.'
    )
    parser.add_argument(
        '-s', '--search',
        metavar='string',
        nargs='+',
        required=True,
        help="String to search in group's description. Use '*' for all groups."
    )
    parser.add_argument(
        '-o', '--outfile',
        metavar='string',
        required=True,
        help='Output json file name (without extension).'
    )
    parser.add_argument(
        '-t', '--title',
        metavar='string',
        required=True,
        help='Tab title for the Navigator layer.'
    )
    parser.add_argument(
        '--merge-tech',
        default=True,
        action=argparse.BooleanOptionalAction,
        help='Increment parent technique score when sub-technique is used (default: enabled).'
    )
    parser.add_argument(
        '--threshold',
        type=positive_int,
        default=0,
        help='Filter out parent techniques with score below this value.'
    )

    args = parser.parse_args()

    stix_file = None
    temp_dir = None

    try:
        # Download STIX data
        stix_file = download_stix_data()
        temp_dir = os.path.dirname(stix_file)

        # Get version info from downloaded file
        print('[+] Detecting version info')
        attack_version = get_attack_version(stix_file)
        navigator_version = get_latest_navigator_version()
        print(f'[-] ATT&CK version: {attack_version}')
        print(f'[-] Navigator version: {navigator_version}')
        print(f'[-] Layer format: {LAYER_VERSION}')

        # Load data using mitreattack-python
        print('[+] Loading ATT&CK data')
        mitre = MitreAttackData(stix_file)

        # Search for matching groups
        print('[+] The following verticals have been selected:')
        for term in args.search:
            print(f'[-] {term.capitalize()}')

        groups = search_groups(mitre, args.search)

        print(f"[+] The following groups have been identified targeting: {', '.join(args.search)}")
        for group in groups:
            print(f"[-] {group.name}")

        # Aggregate techniques
        print(f"[+] Merging techniques from {len(groups)} different groups.")
        technique_scores = aggregate_techniques(mitre, groups, args.merge_tech)

        # Apply threshold filter
        if args.threshold > 0:
            print(f'[+] Filtering out Techniques with score < {args.threshold}')
            technique_scores = filter_by_threshold(technique_scores, args.threshold)

        # Build and save layer
        print('[+] Building Navigator layer')
        layer = build_layer(args.title, technique_scores, attack_version, navigator_version)

        # Save to file
        output_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            f"{args.outfile}.json"
        )
        layer.to_file(output_path)
        print(f'[+] Processing done! Output saved to {output_path}')

    finally:
        # Clean up temp directory
        if temp_dir and 'attack_stix_' in temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == '__main__':
    main()
