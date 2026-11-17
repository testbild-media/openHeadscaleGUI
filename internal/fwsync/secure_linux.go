//go:build linux

package fwsync

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

// ownerUID returns the owner of path (the ohg service user).
func ownerUID(path string) (int, error) {
	st, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("unbekanntes Dateisystem")
	}
	return int(sys.Uid), nil
}

// readDesiredSecure reads the port list written by ohg. It runs as root on
// a file in a directory ohg controls, so it refuses symlinks, anything but
// a regular file owned by the ohg user, and oversized files.
func readDesiredSecure(path string, uid int) ([]Port, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil // no forwards yet
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	sys, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !fi.Mode().IsRegular():
		return nil, errors.New("keine reguläre Datei")
	case !ok || int(sys.Uid) != uid:
		return nil, fmt.Errorf("gehört nicht dem ohg-Benutzer (uid %d)", uid)
	case fi.Size() > maxDesiredSize:
		return nil, errors.New("zu groß")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxDesiredSize+1))
	if err != nil {
		return nil, err
	}
	var d Desired
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, errors.New("ungültiges Format")
	}
	if len(d.Ports) > maxPorts {
		return nil, errors.New("zu viele Ports")
	}
	return d.Ports, nil
}
