#!/usr/bin/env python3
import os
import argparse

# --- CONFIGURATION ---
# Directories to completely ignore by name (build artifacts, git, autotools cache)
IGNORE_DIR_NAMES = {
    '.git', '.svn', '.deps', '.libs', 'autom4te.cache', 
    'build', 'target', 'bin', 'obj', 'node_modules', 'venv'
}

# File extensions to ignore (compiled binaries, objects, etc.)
IGNORE_EXTS = {
    '.o', '.a', '.so', '.lo', '.la', '.exe', '.dll', '.pyc',
    '.png', '.jpg', '.jpeg', '.gif', '.pdf', '.zip', '.tar', '.gz'
}

# Specific exact filenames to ignore (autotools generated files + self-output)
IGNORE_FILES = {
    'configure', 'config.status', 'config.log', 'libtool', 
    'Makefile', 'Makefile.in', 'aclocal.m4', 
    'compile', 'depcomp', 'install-sh', 'missing', 'test-driver',
    'ai_prompt_bundle.txt'
}

def should_include_file(file_name):
    if file_name in IGNORE_FILES:
        return False
    
    _, ext = os.path.splitext(file_name)
    if ext.lower() in IGNORE_EXTS:
        return False
        
    if file_name.startswith('.') and file_name not in {'.gitignore', '.clang-format'}:
        return False

    return True

def generate_tree_and_collect_files(start_path, custom_ignores):
    tree_lines = []
    collected_files = []
    
    # Normalize custom ignore paths to ensure cross-platform matching
    custom_ignores = [os.path.normpath(p) for p in custom_ignores]

    for root, dirs, files in os.walk(start_path):
        rel_root = os.path.relpath(root, start_path)
        
        valid_dirs = []
        for d in dirs:
            # 1. Ignore by predefined name or hidden status
            if d in IGNORE_DIR_NAMES or d.startswith('.'):
                continue
            
            # 2. Ignore by specific custom relative path
            rel_dir_path = os.path.normpath(os.path.join(rel_root, d)) if rel_root != '.' else d
            
            # Check if this directory path matches or is a subfolder of a custom ignore
            if any(rel_dir_path == ci or rel_dir_path.startswith(ci + os.sep) for ci in custom_ignores):
                continue
                
            valid_dirs.append(d)
            
        # Mutate dirs in-place so os.walk skips the ignored directories entirely
        dirs[:] = valid_dirs
        
        # Calculate tree depth for formatting
        level = root.replace(start_path, '').count(os.sep)
        indent = ' ' * 4 * level
        basename = os.path.basename(root)
        if basename and root != start_path:
            tree_lines.append(f"{indent}{basename}/")
        elif root == start_path:
            tree_lines.append(f"{os.path.basename(os.path.abspath(start_path))}/")
        
        subindent = ' ' * 4 * (level + 1) if root != start_path else ' ' * 4
        for f in sorted(files):
            if should_include_file(f):
                tree_lines.append(f"{subindent}{f}")
                collected_files.append(os.path.join(root, f))
                
    return tree_lines, collected_files

def main():
    # Dynamically determine the project root (one level up from this script's location)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_root = os.path.abspath(os.path.join(script_dir, '..'))
    
    # Default output should land in the user's current working directory
    default_output = os.path.join(os.getcwd(), "ai_prompt_bundle.txt")

    parser = argparse.ArgumentParser(description="Bundle C++ Autotools project for AI context.")
    parser.add_argument("project_root", nargs="?", default=default_root, help="Root directory of the project")
    parser.add_argument("-i", "--ignore", action="append", default=[], 
                        help="Specific directory path to ignore (can be used multiple times)")
    parser.add_argument("-o", "--output", default=default_output, help="Output file name")
    
    args = parser.parse_args()

    print(f"Scanning directory: {os.path.abspath(args.project_root)}")
    if args.ignore:
        print(f"Ignoring custom paths: {', '.join(args.ignore)}")
        
    tree_lines, collected_files = generate_tree_and_collect_files(args.project_root, args.ignore)
    
    print(f"Found {len(collected_files)} source files. Bundling...")

    with open(args.output, 'w', encoding='utf-8') as out_file:
        out_file.write("=" * 80 + "\n")
        out_file.write("PROJECT DIRECTORY STRUCTURE\n")
        out_file.write("=" * 80 + "\n\n")
        out_file.write('\n'.join(tree_lines))
        out_file.write("\n\n")
        
        for file_path in collected_files:
            relative_path = os.path.relpath(file_path, args.project_root)
            out_file.write("\n" + "=" * 80 + "\n")
            out_file.write(f"FILE: {relative_path}\n")
            out_file.write("=" * 80 + "\n\n")
            
            try:
                with open(file_path, 'r', encoding='utf-8') as in_file:
                    out_file.write(in_file.read())
            except UnicodeDecodeError:
                out_file.write("[Error: Could not decode file as UTF-8 text. Skipping binary/corrupted content.]\n")
            
            out_file.write("\n")

    print(f"Done! Bundle saved to: {args.output}")

if __name__ == "__main__":
    main()