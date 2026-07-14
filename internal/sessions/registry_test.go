package sessions

import (
	"errors"
	"sync"
	"testing"
)

func TestRegistry_RegisterListGetDeregister(t *testing.T) {
	r := NewRegistry()
	id, dereg := r.Register(Info{User: "alice", SourceIP: "10.0.0.1", Target: "db:5432"}, nil)
	if id == "" {
		t.Fatal("expected an id")
	}
	if got := r.List(); len(got) != 1 || got[0].User != "alice" {
		t.Fatalf("list = %+v", got)
	}
	if info, ok := r.Get(id); !ok || info.Target != "db:5432" {
		t.Fatalf("get = %+v ok=%v", info, ok)
	}
	dereg()
	if got := r.List(); len(got) != 0 {
		t.Fatalf("after deregister, list = %+v", got)
	}
}

func TestRegistry_Terminate(t *testing.T) {
	r := NewRegistry()
	killed := false
	id, _ := r.Register(Info{User: "bob"}, func() error { killed = true; return nil })
	if err := r.Terminate(id); err != nil {
		t.Fatal(err)
	}
	if !killed {
		t.Fatal("terminate hook not called")
	}
	if err := r.Terminate("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown id: want ErrNotFound, got %v", err)
	}
	id2, _ := r.Register(Info{User: "carol"}, nil)
	if err := r.Terminate(id2); !errors.Is(err, ErrNotTerminable) {
		t.Fatalf("no hook: want ErrNotTerminable, got %v", err)
	}
}

func TestRegistry_ConcurrentAccess(t *testing.T) {
	r := NewRegistry()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, dereg := r.Register(Info{User: "u"}, func() error { return nil })
			r.AddChannels(id, 2)
			_ = r.List()
			_, _ = r.Get(id)
			dereg()
		}()
	}
	wg.Wait()
	if got := r.List(); len(got) != 0 {
		t.Fatalf("expected empty after all deregister, got %d", len(got))
	}
}
