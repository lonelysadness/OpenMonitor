package process

import (
	"os"
	"testing"
)

func BenchmarkGetProcess(b *testing.B) {
	pid := uint32(os.Getpid())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := GetOrFindProcess(pid)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkProcessCache(b *testing.B) {
	pid := uint32(os.Getpid())
	proc, _ := GetOrFindProcess(pid)
	key := proc.GetKey()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		globalCache.Get(key)
	}
}
