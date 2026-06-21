package importer

import (
	"path"
	"strings"
)

// imageExtensions are the binary image types v1 import extracts.
var imageExtensions = map[string]string{
	".png":  "image/png",
	".jpg":  "image/jpeg",
	".jpeg": "image/jpeg",
	".gif":  "image/gif",
	".webp": "image/webp",
	".bmp":  "image/bmp",
	".svg":  "image/svg+xml",
}

func basename(name string) string {
	return path.Base(name)
}

// isImageRef reports whether a reference looks like an image based on
// its declared MIME type or filename extension. This is a hint for the
// parser; the job loop still sniffs the actual bytes before upload.
func isImageRef(mimeType, name string) bool {
	if strings.HasPrefix(strings.ToLower(mimeType), "image/") {
		return true
	}
	_, ok := imageExtensions[strings.ToLower(path.Ext(name))]
	return ok
}

// mimeFromExtension returns a best-effort MIME type for a filename, or
// empty when the extension is unknown.
func mimeFromExtension(name string) string {
	return imageExtensions[strings.ToLower(path.Ext(name))]
}
