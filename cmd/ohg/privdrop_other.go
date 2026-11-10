//go:build !linux

package main

func dropPrivileges(dataDir string) {}

func refuseRootServe(dataDir string) {}
