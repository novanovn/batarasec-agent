package queue

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"time"

	bolt "go.etcd.io/bbolt"
	"github.com/batarasec/agent/pkg/findings"
)

var bucketQueue = []byte("send_queue")

const (
	maxRetentionDays = 7
	maxAttempts      = 10
)

// Entry represents a queued chunk of findings that failed to send.
type Entry struct {
	ID         string             `json:"id"`
	JobID      string             `json:"job_id"`
	ChunkIndex int                `json:"chunk_index"`
	Findings   []findings.Finding `json:"findings"`
	CreatedAt  time.Time          `json:"created_at"`
	Attempts   int                `json:"attempts"`
	NextRetry  time.Time          `json:"next_retry"`
}

// Queue is a bbolt-backed offline queue for unsent findings.
type Queue struct {
	db *bolt.DB
}

func Open(path string) (*Queue, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open queue db: %w", err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucketQueue)
		return err
	}); err != nil {
		db.Close()
		return nil, err
	}
	return &Queue{db: db}, nil
}

func (q *Queue) Close() error { return q.db.Close() }

// Push adds a failed chunk to the offline queue.
func (q *Queue) Push(e Entry) error {
	if e.ID == "" {
		e.ID = fmt.Sprintf("%d-%d", time.Now().UnixNano(), rand.Int63())
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	e.NextRetry = time.Now().UTC()

	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return q.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketQueue).Put([]byte(e.ID), data)
	})
}

// Drain processes all due entries. sendFn is called for each entry; on success
// the entry is removed, on failure the entry's NextRetry is updated with
// exponential backoff and it stays in the queue.
func (q *Queue) Drain(sendFn func(e Entry) error) error {
	now := time.Now().UTC()

	var due []Entry
	if err := q.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketQueue).ForEach(func(k, v []byte) error {
			var e Entry
			if err := json.Unmarshal(v, &e); err != nil {
				return nil
			}
			if !e.NextRetry.After(now) {
				due = append(due, e)
			}
			return nil
		})
	}); err != nil {
		return err
	}

	for _, e := range due {
		err := sendFn(e)
		if err == nil {
			// Success — remove from queue.
			_ = q.db.Update(func(tx *bolt.Tx) error {
				return tx.Bucket(bucketQueue).Delete([]byte(e.ID))
			})
			continue
		}

		e.Attempts++
		// Exponential backoff: 2^attempts minutes, capped at 4 hours.
		backoff := time.Duration(1<<uint(e.Attempts)) * time.Minute
		if backoff > 4*time.Hour {
			backoff = 4 * time.Hour
		}
		e.NextRetry = now.Add(backoff)

		data, _ := json.Marshal(e)
		_ = q.db.Update(func(tx *bolt.Tx) error {
			return tx.Bucket(bucketQueue).Put([]byte(e.ID), data)
		})
	}

	return nil
}

// Prune removes entries older than maxRetentionDays or that exceeded maxAttempts.
func (q *Queue) Prune() (int, error) {
	cutoff := time.Now().UTC().AddDate(0, 0, -maxRetentionDays)
	var count int
	return count, q.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketQueue)
		var toDelete [][]byte
		_ = b.ForEach(func(k, v []byte) error {
			var e Entry
			if err := json.Unmarshal(v, &e); err != nil {
				toDelete = append(toDelete, append([]byte(nil), k...))
				return nil
			}
			if e.CreatedAt.Before(cutoff) || e.Attempts >= maxAttempts {
				toDelete = append(toDelete, append([]byte(nil), k...))
			}
			return nil
		})
		for _, k := range toDelete {
			if err := b.Delete(k); err != nil {
				return err
			}
			count++
		}
		return nil
	})
}
