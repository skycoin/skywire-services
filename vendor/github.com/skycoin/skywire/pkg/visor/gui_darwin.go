//go:build darwin && !withoutsystray
// +build darwin,!withoutsystray

package visor

import (
	"os"
)

const (
	deinstallerPath = "/Applications/Skywire.app/Contents/MacOS/deinstaller"
	appPath         = "/Applications/Skywire.app"
	iconName        = "icon.tiff"
)

func checkIsPackage() bool {
	_, err := os.Stat(deinstallerPath)
	return err == nil
}

func isRoot() bool {
	return false
}
