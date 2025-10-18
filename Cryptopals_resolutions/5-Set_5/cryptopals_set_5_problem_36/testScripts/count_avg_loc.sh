#!/bin/bash
# filepath: count_avg_loc.sh
#
# count_avg_loc.sh - Count total and average lines of C++ source/header files
#
# Description:
#   Searches recursively from the script's current directory for C++ source
#   and header files (*.cpp, *.hpp), counts total lines across those files,
#   and computes the average lines per file.
#
# Usage:
#   ./count_avg_loc.sh
#
# Output:
#   - If files are found:
#       Total files: <number>
#       Total lines: <number>
#       Average lines per file: <number with 2 decimal places>
#   - If no files are found:
#       "No source files found."
#
# Notes:
#   - The script uses `find` to locate files and `wc -l` to count lines.
#   - The average is calculated using `bc` with scale=2.
#   - No changes are made to the repository; the script is read-only.
#
# Example:
#   $ ./count_avg_loc.sh
#   Total files: 10
#   Total lines: 1200
#   Average lines per file: 120.00
#

# Find all C++ source/header files
files=$(find . -type f \( -name "*.cpp" -o -name "*.hpp" \))

# Count total lines and number of files
total_lines=0
file_count=0

for file in $files; do
    lines=$(wc -l < "$file")
    total_lines=$((total_lines + lines))
    file_count=$((file_count + 1))
done

if [ $file_count -eq 0 ]; then
    echo "No source files found."
else
    avg=$(echo "scale=2; $total_lines / $file_count" | bc)
    echo "Total files: $file_count"
    echo "Total lines: $total_lines"
    echo "Average lines per file: $avg"
fi