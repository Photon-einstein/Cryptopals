#!/bin/bash
# filepath: count_avg_loc.sh

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