package main
import (
    "os"
    "path/filepath"
)

func ReadReport(name string) ([]byte, error) {
    clean := filepath.Base(name)
    return os.ReadFile("/var/reports/" + clean)
}
