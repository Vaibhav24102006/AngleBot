"""Script to create all required files in angelguard structure."""
import os

# Create all __init__.py files
init_files = {
    'monitor/__init__.py': '"""File monitoring module."""',
    'analysis/__init__.py': '"""Static analysis module."""',
    'ml/__init__.py': '"""Machine learning module."""',
    'ai/__init__.py': '"""AI/LLM explanation module."""',
    'ai/providers/__init__.py': '"""LLM provider implementations."""',
    'decision/__init__.py': '"""Decision engine module."""',
    'ui/__init__.py': '"""UI module."""',
    'logging/__init__.py': '"""Logging module."""',
    'config/__init__.py': '"""Configuration module."""',
}

for filepath, content in init_files.items():
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w') as f:
        f.write(content + '\n')
    print(f"Created {filepath}")

print("All __init__.py files created!")
