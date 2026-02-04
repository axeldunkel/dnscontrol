package elitedomains

import (
	"github.com/StackExchange/dnscontrol/v4/models"
	"github.com/StackExchange/dnscontrol/v4/pkg/rejectif"
)

// AuditRecords returns a list of errors corresponding to the records
// that aren't supported by this provider. If all records are
// supported, an empty list is returned.
func AuditRecords(records []*models.RecordConfig) []error {
	a := rejectif.Auditor{}

	// Elitedomains supports: A, AAAA, CNAME, MX, TXT, SPF

	// MX records must have a valid target
	a.Add("MX", rejectif.MxNull)

	// TXT records should not be empty
	a.Add("TXT", rejectif.TxtIsEmpty)

	// TXT records with backslashes can cause issues
	a.Add("TXT", rejectif.TxtHasBackslash)

	return a.Audit(records)
}
