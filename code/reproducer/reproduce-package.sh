#! /bin/bash

"""
The script is a shell script that is used to reproduce a specific version of a package, given a name and version. 
The script performs the following tasks:

1. Parses command-line arguments:
  A. The first argument is the name and version of the package to be reproduced, in the format <package-name>@<version>
  B. The second argument is the directory where the build result should be stored.
  Finds the repository URL for the package using npm view.

2. Clones the repository using git clone.

3. Checks out the right commit using git checkout. 
The commit to checkout is either the commit specified in the gitHead property of the package (obtained using npm view), 
or a branch or tag with a name that matches the version specified. 
If neither the gitHead property nor the branch/tag can be found, the script checks out HEAD.

Calls build-package.sh, passing the package name, working directory, and output directory as arguments.

Overall, the script automates the process of reproducing a specific version of a package, 
including checking out the right commit, building the package, and saving the result to a specified directory.
"""

set -ex

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

spec="$1"
outdir=$(readlink -f "$2")

package="${spec%@*}"
version="${spec##*@}"

echo "Trying to reproduce package $package at version $version."

# Clone repo
for prop in repository.url repository homepage; do
  repoUrl=$(npm view "$spec" "$prop")
  if ! [ -z "$repoUrl" ]; then
    break
  fi
done
if [ -z "$repoUrl" ]; then
  echo "Could not find git repository for $spec."
  exit 1
fi
repoUrl=$(node -e "console.log(require('normalize-git-url')('$repoUrl').url)")
# replace ssh:// with https://
repoUrl=$(echo "$repoUrl" | sed 's#^ssh://#https://#')
package_dir="$package"@"$version"
git clone $repoUrl "$package_dir"
# git clone "$repoUrl" working

# Check out right commit
cd "$package_dir"
# cd working
ref=$(npm view "$spec" gitHead)
if [ -z "$ref" ]; then
  # typical branch names for $version
  candidate_refs="$version v$version v-$version"
  # if $version contains pre-release tags, try those as well; they might be shas
  if [[ "$version" == *-* ]]; then
    candidate_refs="$candidate_refs $(echo ${version#*-} | sed 's/[-.]/ /g')"
  fi

  for candidate_ref in $candidate_refs; do
    ref=$(git rev-parse --verify "$candidate_ref" 2>/dev/null || echo "")
    if ! [ -z "$ref" ]; then
      break
    fi
  done

  if [ -z "$ref" ]; then
    echo "Could not find source commit for version $version; trying HEAD."
    ref=HEAD
  fi
fi
git checkout "$ref"

full_outdir="$outdir-$package_dir"
mkdir -p "$full_outdir"

# Build package
"$SCRIPT_DIR/build-package.sh" "$package" . "$full_outdir"

if [ $? -eq 0 ]; then
  echo "Successfully reproduced package $spec."
else
  echo "Failed to reproduce package $spec."
fi