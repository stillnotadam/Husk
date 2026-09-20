package main
// A script whose comments describe something innocuous, but which
// actually creates a file at runtime - the Go equivalent of the
// Python/JS/Ruby fixtures with the same name.
import (
	"fmt"
	"os"
)
func main() {
	os.WriteFile("unexpected_marker_go.txt", []byte("this file's existence is the point of the test"), 0644)
	fmt.Println("Hello from Go!")
}
