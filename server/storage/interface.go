package storage

// MetaStore holds the methods that are used for a Metadata Store
type MetaStore interface {
	// UpdateCurrent adds new metadata version for the given GUN if and only
	// if it's a new role, or the version is greater than the current version
	// for the role. Otherwise an error is returned.
	UpdateCurrent(gun string, update MetaUpdate) error

	// UpdateMany adds multiple new metadata for the given GUN.  It can even
	// add multiple versions for the same role, so long as those versions are
	// all unique and greater than any current versions.  Otherwise,
	// none of the metadata is added, and an error is be returned.
	UpdateMany(gun string, updates []MetaUpdate) error

	// GetCurrent returns the data part of the metadata for the latest version
	// of the given GUN and role.  If there is no data for the given GUN and
	// role, an error is returned.
	GetCurrent(gun, tufRole string) (data []byte, err error)

	// Delete removes all metadata for a given GUN.  It does not return an
	// error if no metadata exists for the given GUN.
	Delete(gun string) error

	// GetTimestampKey returns the algorithm and public key for the given GUN.
	// If the GUN doesn't exist, returns an error.
	GetTimestampKey(gun string) (algorithm string, public []byte, err error)

	// SetTimeStampKey sets the algorithm and public key for the given GUN if
	// it doesn't already exist.  Otherwise an error is returned.
	SetTimestampKey(gun string, algorithm string, public []byte) error
}
