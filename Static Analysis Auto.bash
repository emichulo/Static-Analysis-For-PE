#!/bin/bash

# Check if a file is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <PE file>"
    exit 1
fi

FILE=$1

# Ensure the file exists
if [ ! -f "$FILE" ]; then
    echo "Error: File not found!"
    exit 1
fi

echo "Starting static analysis for: $FILE"
echo "===================================="

# 1. Check file type
echo "[+] Checking file type..."
file "$FILE"

echo "---------------------------"

# 2. Check entropy using ent
echo "[+] Calculating entropy..."
ENTROPY=$(ent "$FILE" | grep "Entropy" | awk '{print $3}')
echo "    - File Entropy: $ENTROPY"

echo "---------------------------"

# 3. Extract readable strings
echo "[+] Extracting readable strings..."
strings "$FILE" | grep -E "(http|https|\.dll|\.exe|password|admin|cmd|powershell)" | sort -u > strings_output.txt
cat strings_output.txt

echo "---------------------------"

# 4. Identify imported DLLs
echo "[+] Listing imported DLLs..."
python3 -c "
import pefile

pe = pefile.PE('$FILE')
print('    - Imports:')
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print(f'      {entry.dll.decode()}')
"

echo "---------------------------"

#echo "[+] Checking for complex branching..."

# Use lightweight analysis instead of full `aaa`
#BRANCHES=$(r2 -c "aa; afl" "$FILE" | grep -E "jmp|call" | wc -l)

#if [ "$BRANCHES" -gt 20 ]; then
#    echo "    - Warning: The file contains high branching ($BRANCHES branches), which may indicate obfuscation."
#else
#    echo "    - File has normal branching ($BRANCHES branches)."
#fi

#echo "---------------------------"

echo "[+] Checking for dead code..."

# Disassemble and look for unreachable instructions
DEAD_CODE=$(objdump -d "$FILE" | grep -E -A5 "jmp.*0x" | grep "ret" | wc -l)

if [ "$DEAD_CODE" -gt 5 ]; then
    echo "    - Possible dead code detected ($DEAD_CODE instances of unreachable instructions)."
else
    echo "    - No significant dead code detected."
fi

# 7. Detect if the file is packed using DIE
#echo "[+] 5.Checking for packers using DIE..."
#diec "$FILE"

#echo "---------------------------"

# 8. Disassemble using objdump (Optional)
#echo "[+] Extracting assembly instructions..."
#objdump -d "$FILE" | head -n 50 > disassembly_output.txt
#cat disassembly_output.txt

echo "===================================="