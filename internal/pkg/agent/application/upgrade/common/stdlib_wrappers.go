package common

import (
	"io"
	"os"
)

var Copy = io.Copy
var OpenFile = os.OpenFile
var MkdirAll = os.MkdirAll
