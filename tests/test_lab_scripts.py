"""Lab shell scripts must stay executable on Linux (LF, bash shebang)."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_lab_shell_scripts_are_lf_with_bash_shebang():
    scripts = sorted((ROOT / 'tests' / 'labs').glob('*.sh'))
    assert scripts
    for script in scripts:
        data = script.read_bytes()
        assert b'\r' not in data, f'{script.name} has CRLF endings'
        assert data.startswith(b'#!/usr/bin/env bash\n'), script.name


def test_gitattributes_pins_shell_scripts_to_lf():
    attributes = (ROOT / '.gitattributes').read_text(encoding='utf-8')
    assert '*.sh text eol=lf' in attributes
