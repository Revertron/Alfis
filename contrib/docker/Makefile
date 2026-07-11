# Build the Alfis container image locally.
# The Dockerfile compiles from source, so the build context must be the
# repository root (two levels up), not this directory.
HERE := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
ROOT := $(HERE)/../..
IMAGE_NAME := alfis

build:
	docker build -t $(IMAGE_NAME) -f $(HERE)/Dockerfile $(ROOT)
