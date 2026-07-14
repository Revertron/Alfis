#!/bin/sh

# Get the last tag
TAG=$(git describe --abbrev=0 --tags --match="v[0-9]*\.[0-9]*\.[0-9]*" 2>/dev/null)

# Did getting the tag succeed?
if [ $? != 0 ] || [ -z "$TAG" ]; then
  printf -- "unknown"
  exit 0
fi

# Get the current branch
BRANCH=$(git symbolic-ref -q HEAD --short 2>/dev/null)

# Did getting the branch succeed?
if [ $? != 0 ] || [ -z "$BRANCH" ]; then
  BRANCH="master"
fi

# Split out into major, minor and patch numbers
MAJOR=$(echo $TAG | cut -c 2- | cut -d "." -f 1)
MINOR=$(echo $TAG | cut -c 2- | cut -d "." -f 2)
PATCH=$(echo $TAG | cut -c 2- | cut -d "." -f 3)

# Output all three components: a zero patch must not be dropped
# (v0.10.0 was released as "0.10" by the old two-component format)
printf '%s%d.%d.%d' "$PREPEND" "$((MAJOR))" "$((MINOR))" "$((PATCH))"

# Add the build tag on non-master branches
if [ "$BRANCH" != "master" ]; then
  BUILD=$(git rev-list --count $TAG..HEAD 2>/dev/null)

  # Did getting the count of commits since the tag succeed?
  if [ $? != 0 ] || [ -z "$BUILD" ]; then
    printf -- "-unknown"
    exit 0
  fi

  # Is the build greater than zero?
  if [ $((BUILD)) -gt 0 ]; then
      printf -- "-%04d" "$((BUILD))"
  fi
fi