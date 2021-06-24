package proto

// SetDifference returns the certificates in removeFrom not in toRemove.
func SetDifference(removeFrom []*Certificate, toRemove []*Certificate) []*Certificate {
	var difference []*Certificate
	superCerts := make(map[string]struct{}, len(removeFrom))
	for _, cert := range toRemove {
		superCerts[string(cert.Der)] = struct{}{}
	}
	for _, cert := range removeFrom {
		if _, ok := superCerts[string(cert.Der)]; !ok {
			difference = append(difference, cert)
		}
	}
	return difference
}

// SetDifference returns the database elements in the receiver not in toRemove.
func (d *Database) SetDifference(toRemove *Database) *Database {
	var difference *Database = &Database{}
	certDifference := SetDifference(d.Certs, toRemove.Certs)
	difference.Certs = append(difference.Certs, certDifference...)

	toRemoveHashMap := make(map[string]struct{}, len(toRemove.Hashes))
	for _, hash := range toRemove.Hashes {
		toRemoveHashMap[string(hash)] = struct{}{}
	}
	for _, hash := range d.Hashes {
		if _, ok := toRemoveHashMap[string(hash)]; !ok {
			difference.Hashes = append(difference.Hashes, hash)
		}
	}
	return difference
}

// IsEmpty returns whether number of database elements (certs and hashes) is zero.
func (d *Database) IsEmpty() bool {
	return d.Size() == 0
}

// Size returns number of database elements (certs and hashes).
func (d *Database) Size() int {
	return len(d.Certs) + len(d.Hashes)
}
