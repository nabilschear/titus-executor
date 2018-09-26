// nolint: gofmt
// Code generated by go-bindata.
// sources:
// filter.o
// DO NOT EDIT!

package filter

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func bindataRead(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, gz)
	clErr := gz.Close()

	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}
	if clErr != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

type asset struct {
	bytes []byte
	info  os.FileInfo
}

type bindataFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

func (fi bindataFileInfo) Name() string {
	return fi.name
}
func (fi bindataFileInfo) Size() int64 {
	return fi.size
}
func (fi bindataFileInfo) Mode() os.FileMode {
	return fi.mode
}
func (fi bindataFileInfo) ModTime() time.Time {
	return fi.modTime
}
func (fi bindataFileInfo) IsDir() bool {
	return false
}
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var _filterO = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xaa\x77\xf5\x71\x63\x62\x64\x64\x80\x01\x46\x28\x46\x07\x1d\x4c\x08\xb6\x03\x94\x64\x67\x60\x64\xd8\xce\xc0\xc0\x00\x92\x4a\x14\x0e\x00\x8b\x26\x0a\xf9\x80\xe9\xfd\x2a\x10\xb5\xec\x2c\x0c\x0c\x4a\x0c\x0c\x0c\xba\x26\x3c\x60\x7e\xa6\x32\x84\x0e\x65\x66\x61\xe0\x00\xa9\x57\x96\x03\xf3\x25\x58\x18\x18\x56\xfe\x5b\xf9\x0f\x66\x87\xac\x33\x1b\xc4\x3c\x25\x29\x30\x1d\x0e\xb6\xff\xff\x7f\x77\x26\x88\x03\xef\x30\x31\x30\x28\x30\x30\x30\x24\x2b\x7a\x80\xe5\xb7\x43\xf5\x4d\x85\xd2\xc4\xbb\x0b\x66\x8f\x1c\x59\xf6\x38\x16\x24\x26\x67\xa4\x2a\x18\xe9\x19\x60\x09\x34\x24\xd0\x00\x26\x99\x19\x12\xd0\xc4\x2b\xa1\xe2\x13\xd0\xc4\xdb\xc1\x24\x0b\x86\xfa\x78\x06\x06\x06\x01\x06\x56\x0c\xf3\xdd\xc0\xe2\xcc\x18\xe2\x3a\x60\x71\x16\x4c\x07\xe9\x95\xa4\x56\x94\x30\x24\xe7\x24\x16\x17\x67\xa6\x65\xa6\x16\xc5\x67\xe6\xa5\x17\xa5\x16\x17\x23\x0b\xa5\x62\x88\x40\x15\xc5\xa7\x65\xe6\x94\xa4\x16\x61\xaa\x85\x49\xc4\xc7\xe7\x64\x26\xa7\xe6\x15\xa7\x32\xe8\x15\x97\x14\x95\x24\x26\x31\xe8\x15\x57\xe6\x82\x68\x1f\x27\x27\x83\x78\x13\x08\x65\x0c\xa2\x0c\xe3\x8d\xf0\x07\x1d\x51\x20\x13\x1c\x8a\x98\xe0\x07\x34\x31\xf7\xa1\x89\xa3\xa7\x71\x58\xba\x67\x43\x13\x77\xc0\x61\x1f\x7a\x88\x4a\x11\xd0\x3f\x03\x4d\x9c\x03\x8d\xcf\x8e\x43\xff\x0d\x28\x9d\x41\x40\x7f\x22\x54\x3f\x7a\x18\x38\x40\x3d\xca\x8d\x26\x8e\xee\xff\x42\x68\x7e\x41\x07\x01\x50\x85\x2b\x90\xf4\xb1\x20\xd9\x2f\x01\xa5\x01\x01\x00\x00\xff\xff\x49\x38\x36\x2c\x48\x04\x00\x00")

func filterOBytes() ([]byte, error) {
	return bindataRead(
		_filterO,
		"filter.o",
	)
}

func filterO() (*asset, error) {
	bytes, err := filterOBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "filter.o", size: 1096, mode: os.FileMode(420), modTime: time.Unix(1514502228, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func AssetInfo(name string) (os.FileInfo, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, fmt.Errorf("AssetInfo %s not found", name)
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

// _bindata is a table, holding each asset generator, mapped to its name.
var _bindata = map[string]func() (*asset, error){
	"filter.o": filterO,
}

// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"}
// AssetDir("data/img") would return []string{"a.png", "b.png"}
// AssetDir("foo.txt") and AssetDir("notexist") would return an error
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		cannonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(cannonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, fmt.Errorf("Asset %s not found", name)
			}
		}
	}
	if node.Func != nil {
		return nil, fmt.Errorf("Asset %s not found", name)
	}
	rv := make([]string, 0, len(node.Children))
	for childName := range node.Children {
		rv = append(rv, childName)
	}
	return rv, nil
}

type bintree struct {
	Func     func() (*asset, error)
	Children map[string]*bintree
}

var _bintree = &bintree{nil, map[string]*bintree{
	"filter.o": {filterO, map[string]*bintree{}},
}}

// RestoreAsset restores an asset under the given directory
func RestoreAsset(dir, name string) error {
	data, err := Asset(name)
	if err != nil {
		return err
	}
	info, err := AssetInfo(name)
	if err != nil {
		return err
	}
	err = os.MkdirAll(_filePath(dir, filepath.Dir(name)), os.FileMode(0755))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(_filePath(dir, name), data, info.Mode())
	if err != nil {
		return err
	}
	err = os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
	if err != nil {
		return err
	}
	return nil
}

// RestoreAssets restores an asset under the given directory recursively
func RestoreAssets(dir, name string) error {
	children, err := AssetDir(name)
	// File
	if err != nil {
		return RestoreAsset(dir, name)
	}
	// Dir
	for _, child := range children {
		err = RestoreAssets(dir, filepath.Join(name, child))
		if err != nil {
			return err
		}
	}
	return nil
}

func _filePath(dir, name string) string {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(cannonicalName, "/")...)...)
}
