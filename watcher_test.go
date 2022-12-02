package psqlwatcher

import (
	"context"
	"testing"
	"time"

	"github.com/casbin/casbin/v2"
)

func initWithOption(t *testing.T, opt Option) (*Watcher, *casbin.Enforcer) {
	// create watcher.
	// for simple, start a docker container running for test by:
	// docker run -p 5432 -e POSTGRES_PASSWORD=postgres postgres
	w, err := NewWatcherWithConnString(context.Background(), "host=localhost user=postgres password=postgres dbname=postgres port=5432", opt)
	if err != nil {
		t.Fatalf("failed to new watcher: %v, please ensure postgreSQL is running at localhost:5432", err)
	}

	// create enforcer.
	e, err := casbin.NewEnforcer("testdata/rbac_model.conf", "testdata/rbac_policy.csv")
	if err != nil {
		t.Fatalf("failed to new enforcer: %v", err)
	}

	return w, e
}

func TestDefaultWatcher(t *testing.T) {
	w, _ := initWithOption(t, Option{})
	if err := w.SetUpdateCallback(func(s string) {
		t.Fatalf("should not receive self callback %s", s)
	}); err != nil {
		t.Fatalf("failed to set update callback: %v", err)
	}

	if err := w.Update(); err != nil {
		t.Fatalf("failed to update: %v", err)
	}

	time.Sleep(time.Millisecond * 300)
	w.Close()
}

func TestWatcherWithSelfNotify(t *testing.T) {
	w, _ := initWithOption(t, Option{
		NotifySelf: true,
	})

	recv := ""
	if err := w.SetUpdateCallback(func(s string) {
		recv = s
	}); err != nil {
		t.Fatalf("failed to set update callback: %v", err)
	}

	if err := w.Update(); err != nil {
		t.Fatalf("failed to update: %v", err)
	}

	time.Sleep(time.Millisecond * 300)
	w.Close()

	if recv == "" {
		t.Fatal("should receive a callback when notifySelf is enabled")
	}
}

func TestMultipleWatchers(t *testing.T) {
	w1, _ := initWithOption(t, Option{})
	w2, _ := initWithOption(t, Option{})

	recv1, recv2 := "", ""
	if err := w1.SetUpdateCallback(func(s string) {
		recv1 = s
	}); err != nil {
		t.Fatalf("failed to set update callback1: %v", err)
	}

	if err := w2.SetUpdateCallback(func(s string) {
		recv2 = s
	}); err != nil {
		t.Fatalf("failed to set update callback2: %v", err)
	}

	if err := w1.Update(); err != nil {
		t.Fatalf("failed to update: %v", err)
	}

	time.Sleep(time.Millisecond * 300)
	w1.Close()
	w2.Close()

	if recv1 != "" {
		t.Fatalf("w1 should not receive self callback %s", recv1)
	}
	if recv2 == "" {
		t.Fatal("w2 should receive a callback")
	}
}

func TestWatcherAddPolicy(t *testing.T) {
	w, e := initWithOption(t, Option{
		NotifySelf: true,
		LocalID:    "local-id",
	})

	if err := e.SetWatcher(w); err != nil {
		t.Fatalf("failed to set watcher: %v", err)
	}

	recv := ""
	if err := w.SetUpdateCallback(func(s string) {
		recv = s
	}); err != nil {
		t.Fatalf("failed to set update callback: %v", err)
	}

	if _, err := e.AddPolicy("alice", "data2", "read"); err != nil {
		t.Fatalf("failed to update: %v", err)
	}

	time.Sleep(time.Millisecond * 300)
	w.Close()

	if recv != `{"method":"UpdateForAddPolicy","id":"local-id","sec":"p","ptype":"p","new_rules":[["alice","data2","read"]]}` {
		t.Fatalf("unexpected msg: %s", recv)
	}
}

func TestWatcherRemovePolicy(t *testing.T) {
	w, e := initWithOption(t, Option{
		NotifySelf: true,
		LocalID:    "local-id",
	})

	if err := e.SetWatcher(w); err != nil {
		t.Fatalf("failed to set watcher: %v", err)
	}

	recv := ""
	if err := w.SetUpdateCallback(func(s string) {
		recv = s
	}); err != nil {
		t.Fatalf("failed to set update callback: %v", err)
	}

	if _, err := e.RemovePolicy("alice", "data1", "read"); err != nil {
		t.Fatalf("failed to update: %v", err)
	}

	time.Sleep(time.Millisecond * 300)
	w.Close()

	if recv != `{"method":"UpdateForRemovePolicy","id":"local-id","sec":"p","ptype":"p","new_rules":[["alice","data1","read"]]}` {
		t.Fatalf("unexpected msg: %s", recv)
	}
}

func TestWatcherSavePolicy(t *testing.T) {
	w, e := initWithOption(t, Option{
		NotifySelf: true,
		LocalID:    "local-id",
	})

	if err := e.SetWatcher(w); err != nil {
		t.Fatalf("failed to set watcher: %v", err)
	}

	recv := ""
	if err := w.SetUpdateCallback(func(s string) {
		recv = s
	}); err != nil {
		t.Fatalf("failed to set update callback: %v", err)
	}

	if err := e.SavePolicy(); err != nil {
		t.Fatalf("failed to update: %v", err)
	}

	time.Sleep(time.Millisecond * 300)
	w.Close()

	if recv != `{"method":"UpdateForSavePolicy","id":"local-id"}` {
		t.Fatalf("unexpected msg: %s", recv)
	}
}

func TestWatcherAddPolicies(t *testing.T) {
	w, e := initWithOption(t, Option{
		NotifySelf: true,
		LocalID:    "local-id",
	})

	if err := e.SetWatcher(w); err != nil {
		t.Fatalf("failed to set watcher: %v", err)
	}

	recv := ""
	if err := w.SetUpdateCallback(func(s string) {
		recv = s
	}); err != nil {
		t.Fatalf("failed to set update callback: %v", err)
	}

	if _, err := e.AddPolicies([][]string{
		[]string{"alice", "data2", "read"},
		[]string{"alice", "data3", "read"},
	}); err != nil {
		t.Fatalf("failed to update: %v", err)
	}

	time.Sleep(time.Millisecond * 300)
	w.Close()

	if recv != `{"method":"UpdateForAddPolicies","id":"local-id","sec":"p","ptype":"p","new_rules":[["alice","data2","read"],["alice","data3","read"]]}` {
		t.Fatalf("unexpected msg: %s", recv)
	}
}

func TestWatcherRemovePolicies(t *testing.T) {
	w, e := initWithOption(t, Option{
		NotifySelf: true,
		LocalID:    "local-id",
	})

	if err := e.SetWatcher(w); err != nil {
		t.Fatalf("failed to set watcher: %v", err)
	}

	recv := ""
	if err := w.SetUpdateCallback(func(s string) {
		recv = s
	}); err != nil {
		t.Fatalf("failed to set update callback: %v", err)
	}

	if _, err := e.RemovePolicies([][]string{
		[]string{"alice", "data1", "read"},
		[]string{"bob", "data2", "write"},
	}); err != nil {
		t.Fatalf("failed to update: %v", err)
	}

	time.Sleep(time.Millisecond * 300)
	w.Close()

	if recv != `{"method":"UpdateForRemovePolicies","id":"local-id","sec":"p","ptype":"p","new_rules":[["alice","data1","read"],["bob","data2","write"]]}` {
		t.Fatalf("unexpected msg: %s", recv)
	}
}

func TestWatcherUpdatePolicy(t *testing.T) {
	w, e := initWithOption(t, Option{
		NotifySelf: true,
		LocalID:    "local-id",
	})

	if err := e.SetWatcher(w); err != nil {
		t.Fatalf("failed to set watcher: %v", err)
	}

	recv := ""
	if err := w.SetUpdateCallback(func(s string) {
		recv = s
	}); err != nil {
		t.Fatalf("failed to set update callback: %v", err)
	}

	if _, err := e.UpdatePolicy(
		[]string{"alice", "data1", "read"},
		[]string{"alice", "data1", "write"},
	); err != nil {
		t.Fatalf("failed to update: %v", err)
	}

	time.Sleep(time.Millisecond * 300)
	w.Close()

	if recv != `{"method":"UpdateForUpdatePolicy","id":"local-id","sec":"p","ptype":"p","old_rules":[["alice","data1","read"]],"new_rules":[["alice","data1","write"]]}` {
		t.Fatalf("unexpected msg: %s", recv)
	}
}

func TestWatcherUpdatePolicies(t *testing.T) {
	w, e := initWithOption(t, Option{
		NotifySelf: true,
		LocalID:    "local-id",
	})

	if err := e.SetWatcher(w); err != nil {
		t.Fatalf("failed to set watcher: %v", err)
	}

	recv := ""
	if err := w.SetUpdateCallback(func(s string) {
		recv = s
	}); err != nil {
		t.Fatalf("failed to set update callback: %v", err)
	}

	if _, err := e.UpdatePolicies(
		[][]string{[]string{"alice", "data1", "read"}},
		[][]string{[]string{"alice", "data1", "write"}},
	); err != nil {
		t.Fatalf("failed to update: %v", err)
	}

	time.Sleep(time.Millisecond * 300)
	w.Close()

	if recv != `{"method":"UpdateForUpdatePolicies","id":"local-id","sec":"p","ptype":"p","old_rules":[["alice","data1","read"]],"new_rules":[["alice","data1","write"]]}` {
		t.Fatalf("unexpected msg: %s", recv)
	}
}

func TestWatcherWithDefaultCallback(t *testing.T) {
	w1, e1 := initWithOption(t, Option{})
	w2, e2 := initWithOption(t, Option{})

	if err := e1.SetWatcher(w1); err != nil {
		t.Fatalf("failed to set watcher1: %v", err)
	}
	if err := e2.SetWatcher(w2); err != nil {
		t.Fatalf("failed to set watcher2: %v", err)
	}

	if err := w1.SetUpdateCallback(DefaultCallback(e1)); err != nil {
		t.Fatalf("failed to set update callback1: %v", err)
	}
	if err := w2.SetUpdateCallback(DefaultCallback(e2)); err != nil {
		t.Fatalf("failed to set update callback2: %v", err)
	}

	if _, err := e1.AddPolicy("foo", "data1", "read"); err != nil {
		t.Fatalf("failed to update: %v", err)
	}

	time.Sleep(time.Millisecond * 300)
	w1.Close()
	w2.Close()

	policies := e1.GetFilteredPolicy(0, "foo")
	if len(policies) == 1 && policies[0][0] == "foo" && policies[0][1] == "data1" && policies[0][2] == "read" {
		return
	}
	t.Fatalf("unexpected policy: %+v", policies)
}
