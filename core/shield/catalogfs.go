package shield

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// CatalogFS, when set, is where the catalog loaders read rules, scoring sets and the bot catalog instead of the disk:
// the config playground on makit.sh runs the config check in the browser against an embedded copy of the catalog.
var CatalogFS fs.FS

func readCatalog(path string) ([]byte, error) {
	if CatalogFS != nil {
		return fs.ReadFile(CatalogFS, strings.TrimPrefix(filepath.ToSlash(path), "/"))
	}
	return os.ReadFile(path)
}

// globCatalog lists catalog files, leaving out hidden ones: "._probes.yaml" is the AppleDouble shadow macOS adds when
// a catalog is copied from a Mac (tar, scp of an archive), and loading it would stop the gate.
func globCatalog(pattern string) ([]string, error) {
	var files []string
	var err error
	if CatalogFS != nil {
		files, err = fs.Glob(CatalogFS, strings.TrimPrefix(filepath.ToSlash(pattern), "/"))
	} else {
		files, err = filepath.Glob(pattern)
	}
	out := files[:0]
	for _, f := range files {
		if !strings.HasPrefix(filepath.Base(f), ".") {
			out = append(out, f)
		}
	}
	return out, err
}
