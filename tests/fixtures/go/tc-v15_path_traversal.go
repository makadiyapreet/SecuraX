package main
import "os"

func ReadReport(name string) ([]byte, error) {
    return os.ReadFile("/var/reports/" + name)
}
