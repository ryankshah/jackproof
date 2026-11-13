package exposure

import "io/fs"

type emptyFS struct{}

func (emptyFS) Open(name string) (fs.File, error) {
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
}

func (emptyFS) ReadDir(string) ([]fs.DirEntry, error) {
	return nil, nil
}
