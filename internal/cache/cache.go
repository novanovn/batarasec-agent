package cache

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	bucketFileHashes = []byte("file_hashes")
	bucketMeta       = []byte("metadata")
)

// DB is the bbolt-backed delta cache.
// Only one process may open a given path at a time.
type DB struct {
	db *bolt.DB
}

// FileRecord tracks the last-seen state of a scanned manifest file.
type FileRecord struct {
	ContentHash string     `json:"content_hash"` // sha256 of file contents
	ScannedAt   time.Time  `json:"scanned_at"`
	SentAt      *time.Time `json:"sent_at,omitempty"`
}

func Open(path string) (*DB, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open bolt db %s: %w", path, err)
	}

	if err := db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(bucketFileHashes); err != nil {
			return err
		}
		_, err := tx.CreateBucketIfNotExists(bucketMeta)
		return err
	}); err != nil {
		db.Close()
		return nil, fmt.Errorf("init buckets: %w", err)
	}

	return &DB{db: db}, nil
}

func (d *DB) Close() error { return d.db.Close() }

// cacheKey returns sha256(projectID + filePath) as hex.
func cacheKey(projectID, filePath string) []byte {
	sum := sha256.Sum256([]byte(projectID + "\x00" + filePath))
	return []byte(fmt.Sprintf("%x", sum))
}

// IsChanged reports whether the file's content hash differs from the cached value.
// Returns true (process this file) if not yet cached or hash has changed.
func (d *DB) IsChanged(projectID, filePath, contentHash string) (bool, error) {
	var rec FileRecord
	err := d.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketFileHashes).Get(cacheKey(projectID, filePath))
		if v == nil {
			return nil // not cached → treat as changed
		}
		return json.Unmarshal(v, &rec)
	})
	if err != nil {
		return true, err // on error, safer to reprocess
	}
	return rec.ContentHash != contentHash, nil
}

// MarkScanned updates the cached record for a file after parsing.
func (d *DB) MarkScanned(projectID, filePath, contentHash string) error {
	rec := FileRecord{
		ContentHash: contentHash,
		ScannedAt:   time.Now().UTC(),
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return d.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketFileHashes).Put(cacheKey(projectID, filePath), data)
	})
}

// MarkSent records that findings for this file were successfully sent.
func (d *DB) MarkSent(projectID, filePath string) error {
	return d.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketFileHashes)
		v := b.Get(cacheKey(projectID, filePath))
		if v == nil {
			return nil
		}
		var rec FileRecord
		if err := json.Unmarshal(v, &rec); err != nil {
			return err
		}
		now := time.Now().UTC()
		rec.SentAt = &now
		data, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		return b.Put(cacheKey(projectID, filePath), data)
	})
}

// SetMeta stores a metadata key-value pair (e.g. "last_scan").
func (d *DB) SetMeta(key, value string) error {
	return d.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketMeta).Put([]byte(key), []byte(value))
	})
}

// GetMeta retrieves a metadata value.
func (d *DB) GetMeta(key string) (string, error) {
	var val string
	err := d.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketMeta).Get([]byte(key))
		if v != nil {
			val = string(v)
		}
		return nil
	})
	return val, err
}

// PruneOlderThan deletes file records not scanned within the given duration (e.g. 90 days).
func (d *DB) PruneOlderThan(age time.Duration) (int, error) {
	cutoff := time.Now().UTC().Add(-age)
	var count int
	return count, d.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketFileHashes)
		var toDelete [][]byte
		_ = b.ForEach(func(k, v []byte) error {
			var rec FileRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return nil
			}
			if rec.ScannedAt.Before(cutoff) {
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
