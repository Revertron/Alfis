ROOT:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
IMAGE_NAME:=alfis

build:
	docker build -t ${IMAGE_NAME} .
