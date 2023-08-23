package cache_test

import (
	"reflect"
	"sync"
	"testing"
	"unsafe"

	"github.com/frozenpine/pkt4go/cache"
)

func TestOffset(t *testing.T) {
	data := []byte{0, 1, 2, 3, 4, 5, 6, 7}

	buffer := cache.NewBuffer(data)

	offset := 0

	buffer.ReadByte()
	if offset = buffer.Offset(); offset != 1 {
		t.Fatal("Read byte failed.")
	}

	buffer.ReadHShort()
	if offset = buffer.Offset(); offset != 3 {
		t.Fatal("Read short failed")
	}

	buffer.ReadNLong()
	if offset = buffer.Offset(); offset != 7 {
		t.Fatal("Read long failed")
	}

	buffer.Unread(5)
	offset = buffer.Offset()
	cap := buffer.Cap()
	len := buffer.Len()
	if offset != 2 || cap != 8 || len != 6 {
		t.Fatal("Unread failed")
	}
}

func TestPool(t *testing.T) {
	pool := cache.NewBytesPool(0)

	v1 := pool.GetSlice()
	t.Log(len(v1), cap(v1), (*reflect.SliceHeader)(unsafe.Pointer(&v1)).Data)

	v2 := pool.GetSlice()
	t.Log(len(v2), cap(v2), (*reflect.SliceHeader)(unsafe.Pointer(&v2)).Data)

	pool.PutSlice(v1)

	v3 := pool.GetSlice()
	t.Log(len(v3), cap(v3), (*reflect.SliceHeader)(unsafe.Pointer(&v3)).Data)

	pool.PutSlice(make([]byte, 8192))

	for idx := 0; idx < 2; idx++ {
		data := pool.GetSlice()

		t.Log(len(data), cap(data), (*reflect.SliceHeader)(unsafe.Pointer(&data)).Data)
	}
}

func BenchmarkPool(b *testing.B) {
	pool := cache.NewBytesPool(0)

	ch := make(chan []byte, 1)
	wg := sync.WaitGroup{}

	wg.Add(1)
	go func() {
		defer wg.Done()

		for d := range ch {
			pool.PutSlice(d)
		}
	}()

	b.Run("pool", func(b1 *testing.B) {
		for i := 0; i < b1.N; i++ {
			ch <- pool.GetSlice()
		}
	})

	b.Run("make", func(b2 *testing.B) {
		for i := 0; i < b2.N; i++ {
			ch <- make([]byte, cache.MaxBytesSize)
		}
	})

	close(ch)

	wg.Wait()
}
