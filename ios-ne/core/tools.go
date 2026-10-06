//go:build tools

package tools

// Keeps golang.org/x/mobile in go.mod so `gomobile bind` can build the bindings.
import _ "golang.org/x/mobile/bind"
