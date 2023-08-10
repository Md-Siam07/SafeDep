"""
This script is used to extract the contents of multiple ".tgz" files into separate directories. 
The script uses a for loop to iterate through each ".tgz" file in the current directory. 
For each file, it creates a new directory using the name of the file without the ".tgz" extension. 
Then, the script uses the tar command to extract the contents of the ".tgz" file into the newly created directory, 
using the "-xzf" and "-C" flags to specify the extraction and target directory, respectively.
"""

for file in *.tgz; do
    dir=`basename "$file" .tgz`
    mkdir "$dir"
    tar -xzf "$file" -C "$dir"
done
