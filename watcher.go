package psqlwatcher

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Watcher implements casbin Watcher and WatcherEX to sync multiple casbin enforcer.
type Watcher struct {
	sync.RWMutex

	opt        Option
	pool       *pgxpool.Pool
	callback   func(string)
	cancelFunc func()
}

// UpdateType defines the type of update operation.
type UpdateType string

// all types of Update.
const (
	Update                        UpdateType = "Update"
	UpdateForAddPolicy            UpdateType = "UpdateForAddPolicy"
	UpdateForRemovePolicy         UpdateType = "UpdateForRemovePolicy"
	UpdateForRemoveFilteredPolicy UpdateType = "UpdateForRemoveFilteredPolicy"
	UpdateForSavePolicy           UpdateType = "UpdateForSavePolicy"
	UpdateForAddPolicies          UpdateType = "UpdateForAddPolicies"
	UpdateForRemovePolicies       UpdateType = "UpdateForRemovePolicies"
	UpdateForUpdatePolicy         UpdateType = "UpdateForUpdatePolicy"
	UpdateForUpdatePolicies       UpdateType = "UpdateForUpdatePolicies"
)

// MSG defines the payload for message.
type MSG struct {
	Method      UpdateType `json:"method"`
	ID          string     `json:"id"`
	Sec         string     `json:"sec,omitempty"`
	Ptype       string     `json:"ptype,omitempty"`
	OldRules    [][]string `json:"old_rules,omitempty"`
	NewRules    [][]string `json:"new_rules,omitempty"`
	FieldIndex  int        `json:"field_index,omitempty"`
	FieldValues []string   `json:"field_values,omitempty"`
}

// NewWatcherWithConnString creates a Watcher with pgx connection string.
func NewWatcherWithConnString(ctx context.Context, connString string, opt Option) (*Watcher, error) {
	// new the pgx pool by conn string.
	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		return nil, fmt.Errorf("failed to new pgx pool with %s: %v", connString, err)
	}

	return NewWatcherWithPool(ctx, pool, opt)
}

// NewWatcherWithPool creates a Watcher with pgx pool.
func NewWatcherWithPool(ctx context.Context, pool *pgxpool.Pool, opt Option) (*Watcher, error) {
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping pool: %v", err)
	}

	// prepare the watcher.
	listenerCtx, cancel := context.WithCancel(context.Background())
	w := &Watcher{
		opt:        opt,
		pool:       pool,
		cancelFunc: cancel,
	}

	// start listen.
	go func() {
		if err := w.listenMessage(listenerCtx); err == context.Canceled {
			log.Println("[psqlwatcher] watcher closed")
		} else if err != nil {
			log.Printf("[psqlwatcher] failed to listen message: %v\n", err)
		}
	}()

	return w, nil
}

// DefaultCallback defines the generic implementation for WatcherEX interface.
func DefaultCallback(e casbin.IEnforcer) func(string) {
	return func(s string) {
		// parse the msg.
		var m MSG
		if err := json.Unmarshal([]byte(s), &m); err != nil {
			log.Printf("[psqlwatcher] unable to unmarshal %s: %v\n", s, err)
			return
		}

		var res bool
		var err error
		switch m.Method {
		case Update, UpdateForSavePolicy:
			err = e.LoadPolicy()
			res = true
		case UpdateForAddPolicy:
			res, err = e.SelfAddPolicy(m.Sec, m.Ptype, m.NewRules[0])
		case UpdateForAddPolicies:
			res, err = e.SelfAddPolicies(m.Sec, m.Ptype, m.NewRules)
		case UpdateForRemovePolicy:
			res, err = e.SelfRemovePolicy(m.Sec, m.Ptype, m.NewRules[0])
		case UpdateForRemoveFilteredPolicy:
			res, err = e.SelfRemoveFilteredPolicy(m.Sec, m.Ptype, m.FieldIndex, m.FieldValues...)
		case UpdateForRemovePolicies:
			res, err = e.SelfRemovePolicies(m.Sec, m.Ptype, m.NewRules)
		case UpdateForUpdatePolicy:
			res, err = e.SelfUpdatePolicy(m.Sec, m.Ptype, m.OldRules[0], m.NewRules[0])
		case UpdateForUpdatePolicies:
			res, err = e.SelfUpdatePolicies(m.Sec, m.Ptype, m.OldRules, m.NewRules)
		default:
			err = fmt.Errorf("unknown update type: %s", m.Method)
		}
		if err != nil {
			log.Printf("[psqlwatcher] failed to update policy: %v\n", err)
		}
		if !res {
			log.Println("[psqlwatcher] callback update policy failed")
		}
	}
}

// SetUpdateCallback sets the callback function that the watcher will call
// when the policy in DB has been changed by other instances.
// A classic callback is Enforcer.LoadPolicy().
func (w *Watcher) SetUpdateCallback(callback func(string)) error {
	w.Lock()
	defer w.Unlock()
	w.callback = callback
	return nil
}

// Update calls the update callback of other instances to synchronize their policy.
// It is usually called after changing the policy in DB, like Enforcer.SavePolicy(),
// Enforcer.AddPolicy(), Enforcer.RemovePolicy(), etc.
func (w *Watcher) Update() error {
	return w.notifyMessage(&MSG{
		Method: Update,
		ID:     w.GetLocalID(),
	})
}

// Close stops and releases the watcher, the callback function will not be called any more.
func (w *Watcher) Close() {
	// close the listen routine by cancel the context.
	w.cancelFunc()
}

// UpdateForAddPolicy calls the update callback of other instances to synchronize their policy.
// It is called after Enforcer.AddPolicy()
func (w *Watcher) UpdateForAddPolicy(sec, ptype string, params ...string) error {
	return w.notifyMessage(&MSG{
		Method:   UpdateForAddPolicy,
		ID:       w.GetLocalID(),
		Sec:      sec,
		Ptype:    ptype,
		NewRules: [][]string{params},
	})
}

// UpdateForRemovePolicy calls the update callback of other instances to synchronize their policy.
// It is called after Enforcer.RemovePolicy()
func (w *Watcher) UpdateForRemovePolicy(sec, ptype string, params ...string) error {
	return w.notifyMessage(&MSG{
		Method:   UpdateForRemovePolicy,
		ID:       w.GetLocalID(),
		Sec:      sec,
		Ptype:    ptype,
		NewRules: [][]string{params},
	})
}

// UpdateForRemoveFilteredPolicy calls the update callback of other instances to synchronize their policy.
// It is called after Enforcer.RemoveFilteredNamedGroupingPolicy()
func (w *Watcher) UpdateForRemoveFilteredPolicy(sec, ptype string, fieldIndex int, fieldValues ...string) error {
	return w.notifyMessage(&MSG{
		Method:      UpdateForRemoveFilteredPolicy,
		ID:          w.GetLocalID(),
		Sec:         sec,
		Ptype:       ptype,
		FieldIndex:  fieldIndex,
		FieldValues: fieldValues,
	})
}

// UpdateForSavePolicy calls the update callback of other instances to synchronize their policy.
// It is called after Enforcer.RemoveFilteredNamedGroupingPolicy()
func (w *Watcher) UpdateForSavePolicy(model model.Model) error {
	return w.notifyMessage(&MSG{
		Method: UpdateForSavePolicy,
		ID:     w.GetLocalID(),
	})
}

// UpdateForAddPolicies calls the update callback of other instances to synchronize their policy.
// It is called after Enforcer.AddPolicies()
func (w *Watcher) UpdateForAddPolicies(sec string, ptype string, rules ...[]string) error {
	return w.notifyMessage(&MSG{
		Method:   UpdateForAddPolicies,
		ID:       w.GetLocalID(),
		Sec:      sec,
		Ptype:    ptype,
		NewRules: rules,
	})
}

// UpdateForRemovePolicies calls the update callback of other instances to synchronize their policy.
// It is called after Enforcer.RemovePolicies()
func (w *Watcher) UpdateForRemovePolicies(sec string, ptype string, rules ...[]string) error {
	return w.notifyMessage(&MSG{
		Method:   UpdateForRemovePolicies,
		ID:       w.GetLocalID(),
		Sec:      sec,
		Ptype:    ptype,
		NewRules: rules,
	})
}

// UpdateForUpdatePolicy calls the update callback of other instances to synchronize their policy.
// It is called after Enforcer.UpdatePolicy()
func (w *Watcher) UpdateForUpdatePolicy(sec string, ptype string, oldRule, newRule []string) error {
	return w.notifyMessage(&MSG{
		Method:   UpdateForUpdatePolicy,
		ID:       w.GetLocalID(),
		Sec:      sec,
		Ptype:    ptype,
		OldRules: [][]string{oldRule},
		NewRules: [][]string{newRule},
	})
}

// UpdateForUpdatePolicies calls the update callback of other instances to synchronize their policy.
// It is called after Enforcer.UpdatePolicies()
func (w *Watcher) UpdateForUpdatePolicies(sec string, ptype string, oldRules, newRules [][]string) error {
	return w.notifyMessage(&MSG{
		Method:   UpdateForUpdatePolicies,
		ID:       w.GetLocalID(),
		Sec:      sec,
		Ptype:    ptype,
		OldRules: oldRules,
		NewRules: newRules,
	})
}

func (w *Watcher) notifyMessage(m *MSG) error {
	// encode the msg with json.
	b, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("failed to marshal %+v: %v", m, err)
	}
	cmd := fmt.Sprintf("select pg_notify('%s', $1)", w.GetChannel())

	// send to psql channel.
	if _, err := w.pool.Exec(context.Background(), cmd, string(b)); err != nil {
		return fmt.Errorf("failed to notify %s: %v", string(b), err)
	}

	if w.GetVerbose() {
		log.Printf("[psqlwatcher] send message %s to channel %s\n", string(b), w.GetChannel())
	}

	return nil
}

func (w *Watcher) listenMessage(ctx context.Context) error {
	// acquire the psql connection for listening.
	conn, err := w.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("failed to acquire psql connection: %v", err)
	}
	defer conn.Release()

	// listen to the psql channel.
	cmd := fmt.Sprintf("listen %s", w.GetChannel())
	if _, err = conn.Exec(ctx, cmd); err != nil {
		return fmt.Errorf("failed to listen %s: %v", w.GetChannel(), err)
	}

	// wait for psql notification.
	for {
		notification, err := conn.Conn().WaitForNotification(ctx)
		if err == context.Canceled {
			return err
		} else if err != nil {
			return fmt.Errorf("failed to wait for notification: %v", err)
		}

		// print debug message.
		if w.GetVerbose() {
			log.Printf("[psqlwatcher] received message: %s from channel %s with local ID %s", notification.Payload, w.GetChannel(), w.GetLocalID())
		}

		// unmarshal the payload to MSG.
		var m MSG
		if err := json.Unmarshal([]byte(notification.Payload), &m); err != nil {
			log.Printf("failed to unmarshal %s: %v\n", notification.Payload, err)
			continue
		}

		// check with msg ID is self or not.
		// if NotifySelf is enabled, will callback when id is same.
		w.RLock()
		if m.ID != w.GetLocalID() || w.GetNotifySelf() {
			w.callback(notification.Payload)
		}
		w.RUnlock()
	}
}
