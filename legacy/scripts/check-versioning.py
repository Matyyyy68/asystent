#!/usr/bin/env python3
"""Fail when shipped .NET apps stop inheriting the single product version."""
from pathlib import Path
import re
import xml.etree.ElementTree as ET

root = Path(__file__).resolve().parents[1]
props_path = root / "eng/ProductVersion.props"
version = ET.parse(props_path).findtext("./PropertyGroup/VersionPrefix")
if not version or not re.fullmatch(r"\d+\.\d+\.\d+", version):
    raise SystemExit("eng/ProductVersion.props must define a numeric MAJOR.MINOR.PATCH VersionPrefix")

directory_props = ET.parse(root / "Directory.Build.props")
imports = [node.attrib.get("Project", "").replace("\\", "/") for node in directory_props.findall("Import")]
if "eng/ProductVersion.props" not in imports:
    raise SystemExit("Directory.Build.props must import eng/ProductVersion.props")

projects = sorted(path for path in root.rglob("*.csproj") if not ({"bin", "obj"} & set(path.parts)))
if not projects:
    raise SystemExit("No .NET projects found")
overrides = []
for path in projects:
    document = ET.parse(path)
    if any(document.findall(f".//{name}") for name in ("Version", "VersionPrefix", "AssemblyVersion", "FileVersion", "InformationalVersion")):
        overrides.append(str(path.relative_to(root)))
if overrides:
    raise SystemExit("Project-local versions override the product source: " + ", ".join(overrides))

print(f"PASS: {version} is the single version inherited by {len(projects)} .NET projects and the installer packager.")
