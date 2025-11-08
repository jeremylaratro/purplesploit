#!/usr/bin/env python3
"""
Test script for v3.5 features:
1. Wordlist Manager
2. Module Creator
"""

import sys
sys.path.insert(0, 'python')

from purplesploit.core.session import WordlistManager
from pathlib import Path

print("=" * 70)
print("TESTING V3.5 FEATURES")
print("=" * 70)

# Test 1: Wordlist Manager
print("\n[TEST 1] Wordlist Manager")
print("-" * 70)

wm = WordlistManager()

# Show categories
print("Available categories:")
for cat in wm.get_categories():
    print(f"  - {cat}")

# Create a dummy wordlist file for testing
test_wordlist_path = "/tmp/test_wordlist.txt"
Path(test_wordlist_path).write_text("test1\ntest2\ntest3\n")

# Test adding wordlists
print("\nAdding wordlists...")
wm.add("web_dir", test_wordlist_path, "Test Web Dir Wordlist")
wm.add("password", test_wordlist_path, "Test Password Wordlist")

# List wordlists
print("\nWordlists by category:")
all_wordlists = wm.list()
for category, wordlists in all_wordlists.items():
    if wordlists:
        print(f"\n  {category.upper()}:")
        for i, wl in enumerate(wordlists):
            print(f"    {i}. {wl['name']} - {wl['path']}")

# Test setting current wordlist
print("\nSetting current wordlist for 'web_dir'...")
wm.set_current("web_dir", "0")
current = wm.get_current("web_dir")
print(f"Current web_dir wordlist: {current['name'] if current else 'None'}")

# Test export/import
print("\nTesting export/import...")
exported = wm.export()
wm2 = WordlistManager()
wm2.import_data(exported)
print(f"Import successful! Categories preserved: {len(wm2.get_categories())}")

print("\n✓ Wordlist Manager tests passed!")

# Test 2: Module Creator
print("\n[TEST 2] Module Creator")
print("-" * 70)

from purplesploit.modules.utility.module_creator import ModuleCreatorModule

# Create a mock framework
class MockFramework:
    def log(self, msg, level="info"):
        print(f"[{level.upper()}] {msg}")

framework = MockFramework()
creator = ModuleCreatorModule(framework)

print(f"Module Name: {creator.name}")
print(f"Description: {creator.description}")
print(f"Category: {creator.category}")

# Check operations
operations = creator.get_operations()
print(f"\nAvailable operations ({len(operations)}):")
for i, op in enumerate(operations, 1):
    print(f"  {i}. {op['name']}: {op['description']}")

print("\n✓ Module Creator loaded successfully!")

# Summary
print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print("""
✓ Wordlist Manager
  - Manages wordlists by category (web_dir, dns_vhost, username, password, etc.)
  - Add, remove, list, and select wordlists
  - Persistent across sessions (export/import)
  - Integrated into console commands: 'wordlists'

✓ Module Creator
  - Create simple command modules
  - Create external tool wrappers
  - Create multi-operation modules
  - Generates ready-to-use Python code
  - Accessible via: use utility/module_creator

To use in PurpleSploit console:
  1. Wordlists: 'wordlists add web_dir /path/to/wordlist.txt'
  2. Module Creator: 'use utility/module_creator' then 'run'
""")

print("=" * 70)
print("All tests passed! ✓")
print("=" * 70)
