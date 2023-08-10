#! /bin/bash

"""
The script is a bash shell script designed to automate the build process for a Node.js package.

The script takes three arguments:
A. package-name: the name of the package to build
B. working-dir: the working directory where the package source code is located
C. out-dir: the directory where the built package tarball should be extracted to.

Here is what the script does in detail:
1. It checks if the number of arguments passed to the script is equal to 3, 
   and if not, it displays a usage message and exits with a status code of 1.

2. It sets three variables pkgName, working, and outdir to the first, second, 
   and third arguments, respectively. The outdir variable is converted to an absolute path using the readlink -f command.

3. The script then changes the current working directory to the working directory using cd.

4. The script outputs the current Git commit hash using git rev-parse HEAD.

5. The script then finds the directory containing a package.json file with the same name as the package using the find command. 
   It uses the jq command to extract the "name" field from the package.json file and compares it to the pkgName variable. 
   The path to the directory is saved in the pkgDir variable.

6. The script then runs npm install with the --production=false option in the root directory to install dependencies for the package.

7. If pkgDir is not an empty string and is different from the current directory, 
   the script changes the current working directory to pkgDir and runs 
   npm install with the --production=false option to install dependencies specific to the package directory.

8. The script then attempts to set the system time to the time of publication of the package using npm view, jq, and sudo date -s. 
   If this fails, a message is printed.

9. The script runs various possible build scripts (compile, build, pack, and webpack) 
   using npm run and the timeout command with a 10-minute timeout.

10. The script then creates a tarball of the package using npm pack and saves the path to the tarball in the tarball variable.

11. The script resets the system time to the value saved in the now variable.

12. The script creates the outdir directory using mkdir -p and then extracts the tarball to outdir using tar xf.

The set -ex at the beginning of the script sets the -e (errexit) and -x (xtrace) options, 
causing the script to exit immediately if a command returns a non-zero exit status, and display each command as it is executed.
"""

set -ex

if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <package-name> <working-dir> <out-dir>"
    exit 1
fi

pkgName="$1"
working="$2"
outdir=$(readlink -f $3)

cd "$working"
git rev-parse HEAD

# find directory containing package.json file with the same name as the package
# we sort the paths so that shallower ones are preferred over deeper ones
pkgDir=$(find . -name package.json | while read pkg; do test $(jq -r .name $pkg) = "$pkgName" && echo $pkg; done | xargs dirname | sort | head -n 1)

# first install dependencies in the root
npm install --production=false || echo "Dependency installation failed; continuing."

# then install dependencies in the package directory (if different from root)
if ! [ -z "$pkgDir" ] && [ "$pkgDir" != "." ]; then
  cd "$pkgDir"
  npm install --production=false || echo "Dependency installation failed; continuing."
fi

# attempt to set the time to the time of publication
now=$(date)
(npm view "$pkgName" time --json | jq ".[\"$version\"]" | xargs sudo -n date -s) || \
  (echo "Failed to set date; continuing.")

# run a few possible build scripts under a 10-minute timeout
echo "run a few possible build scripts under a 10-minute timeout"
for target in compile build pack webpack; do
  for prefix in "" "our:"; do
    timeout 10m npm run "$prefix$target" || true
  done
done
tarball=$(npm pack | tail -n 1)

# reset time
sudo -n date -s "$now" || echo "Failed to reset time; continuing."

mkdir -p "$outdir"
tar xf "$tarball" -C "$outdir" --strip-components=1

if [ $? -eq 0 ]; then
  echo "Successfully build $spec."
else
  echo "Failed to build $spec."
fi