package psqlwatcher

import "github.com/google/uuid"

const defaultChannel = "casbin_psql_watcher"

// Option is used for configure watcher.
type Option struct {
	// Channel defines which psql channel to use.
	// use default channel if not specified.
	Channel string
	// Verbose indicate whether to output info log.
	Verbose bool
	// LocalID indicates the watcher's local ID, used to ignore self update event.
	// generate a random id if not specified.
	LocalID string
	// NotifySelf will notify change to the same watcher to do the update.
	// only for testing or debug usage.
	NotifySelf bool
}

// GetChannel gets the channel for the option.
func (w *Watcher) GetChannel() string {
	if w.opt.Channel == "" {
		w.opt.Channel = defaultChannel
	}
	return w.opt.Channel
}

// GetVerbose gets the verbose for the option.
func (w *Watcher) GetVerbose() bool {
	return w.opt.Verbose
}

// GetLocalID gets the local ID for the option.
func (w *Watcher) GetLocalID() string {
	if w.opt.LocalID == "" {
		w.opt.LocalID = uuid.New().String()
	}
	return w.opt.LocalID
}

// GetNotifySelf gets the NotifySelf for the option.
func (w *Watcher) GetNotifySelf() bool {
	return w.opt.NotifySelf
}
