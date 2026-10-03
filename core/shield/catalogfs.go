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

func globCatalog(pattern string) ([]string, error) {
	if CatalogFS != nil {
		return fs.Glob(CatalogFS, strings.TrimPrefix(filepath.ToSlash(pattern), "/"))
	}
	return filepath.Glob(pattern)
}
