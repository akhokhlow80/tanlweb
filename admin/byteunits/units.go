package byteunits

import "fmt"

func PrettyPrint(bytes int64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	} else if bytes < 1024*1024 {
		return fmt.Sprintf("%.2f KiB", float32(bytes)/1024)
	} else if bytes < 1024*1024*1024 {
		return fmt.Sprintf("%.2f MiB", float32(bytes)/1024/1024)
	} else if bytes < 1024*1024*1024*1024 {
		return fmt.Sprintf("%.2f GiB", float32(bytes)/1024/1024/1024)
	} else {
		return fmt.Sprintf("%.2f TiB", float32(bytes)/1024/1024/1024/1024)
	}
}
