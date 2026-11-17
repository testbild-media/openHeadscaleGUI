//go:build !linux

package fwsync

import "errors"

var errOnlyLinux = errors.New("die Firewall-Freigabe gibt es nur unter Linux")

func ownerUID(string) (int, error) { return 0, errOnlyLinux }

func readDesiredSecure(string, int) ([]Port, error) { return nil, errOnlyLinux }
