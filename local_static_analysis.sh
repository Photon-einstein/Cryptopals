#!/bin/bash

# Ensure the script is running in a clean environment (avoid shell profile issues)
if [[ -z "$PS1" ]]; then
    echo "Running in non-interactive shell. Proceeding with static analysis..."
else
    echo "Warning: Running in interactive shell. Consider using 'bash --noprofile --norc' to avoid conflicts."
fi

# Update PATH to ensure common directories are included
export PATH=$PATH:/usr/bin:/usr/local/bin

# Debugging step: print the current PATH
echo "Current PATH: $PATH"

# Ensure Clang-Tidy and Cppcheck are installed
if ! which clang-tidy &>/dev/null || ! which  cppcheck &>/dev/null; then
    echo "Error: Clang-Tidy or Cppcheck is not installed. Install them first."
    exit 1
fi

echo "🔍 Searching for CMakeLists.txt files..."

# Find all directories containing a CMakeLists.txt file, excluding 'build' directories and everything inside them
find . -type f -name "CMakeLists.txt" ! -path "*/build/*" | while read cmake_file; do
    dir=$(dirname "$cmake_file")
    src_dir="$dir/src"
    
    # Run Clang-Tidy only if a src/ folder exists
    if [ -d "$src_dir" ]; then
        echo "🚀 Running Clang-Tidy in $src_dir"
        for file in "$src_dir"/*.cpp; do
            [ -f "$file" ] && clang-tidy "$file" -- -I"$src_dir"
        done
    fi

    # Run Clang-Tidy on cpp files in the 'tests' folder as well
    if [ -d "$dir/tests" ]; then
        echo "🚀 Running Clang-Tidy in $dir/tests"
        for file in "$dir/tests"/*.cpp; do
            [ -f "$file" ] && clang-tidy "$file" -- -I"$dir/tests"
        done
    fi

    # Run Cppcheck only if a src/ folder exists
    if [ -d "$src_dir" ]; then
        echo "🚀 Running Cppcheck in $src_dir"
        cppcheck --enable=all --inconclusive --force --error-exitcode=1 "$src_dir" --suppress=missingIncludeSystem
    fi

    # Run Cppcheck file by file in the 'tests' folder
    if [ -d "$dir/tests" ]; then
        echo "🚀 Running Cppcheck file by file in $dir/tests"
        for file in "$dir/tests"/*.cpp; do
            [ -f "$file" ] && cppcheck --enable=all --inconclusive  --force --error-exitcode=1 "$file" --suppress=missingIncludeSystem
        done
    fi
done

echo "✅ Static analysis completed."