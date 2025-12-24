package mailbox

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mnohosten/esp/internal/database"
)

// SearchCriteria defines IMAP search parameters
type SearchCriteria struct {
	// Flag criteria
	All        bool
	Answered   bool
	Deleted    bool
	Draft      bool
	Flagged    bool
	New        bool // Recent AND NOT Seen
	Recent     bool
	Seen       bool
	Unanswered bool
	Undeleted  bool
	Undraft    bool
	Unflagged  bool
	Unseen     bool

	// Date criteria (internal date)
	Before *time.Time
	On     *time.Time
	Since  *time.Time

	// Sent date criteria (Date header)
	SentBefore *time.Time
	SentOn     *time.Time
	SentSince  *time.Time

	// Size criteria
	Larger  int64
	Smaller int64

	// Header criteria
	From    string
	To      string
	Cc      string
	Bcc     string
	Subject string
	Header  map[string]string // Generic header search

	// Body criteria
	Body string // Search in body
	Text string // Search in headers and body

	// UID criteria
	UIDs []uint32

	// Sequence set criteria
	SeqNums []uint32

	// Logical operators
	Not *SearchCriteria
	Or  []*SearchCriteria
}

// Searcher handles message search operations
type Searcher struct {
	db *database.DB
}

// NewSearcher creates a new searcher
func NewSearcher(db *database.DB) *Searcher {
	return &Searcher{db: db}
}

// Search performs a search on messages in a mailbox
func (s *Searcher) Search(ctx context.Context, mailboxID uuid.UUID, criteria *SearchCriteria) ([]uint32, error) {
	query, args := s.buildQuery(mailboxID, criteria)

	rows, err := s.db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("search failed: %w", err)
	}
	defer rows.Close()

	var uids []uint32
	for rows.Next() {
		var uid uint32
		if err := rows.Scan(&uid); err != nil {
			return nil, fmt.Errorf("failed to scan uid: %w", err)
		}
		uids = append(uids, uid)
	}

	return uids, nil
}

// SearchFTS performs a full-text search on messages
func (s *Searcher) SearchFTS(ctx context.Context, mailboxID uuid.UUID, query string) ([]uint32, error) {
	// Use PostgreSQL full-text search
	sqlQuery := `
		SELECT uid FROM messages
		WHERE mailbox_id = $1
		AND to_tsvector('english', COALESCE(subject, '') || ' ' || COALESCE(body_text, '')) @@ plainto_tsquery('english', $2)
		ORDER BY uid
	`

	rows, err := s.db.Pool.Query(ctx, sqlQuery, mailboxID, query)
	if err != nil {
		return nil, fmt.Errorf("FTS search failed: %w", err)
	}
	defer rows.Close()

	var uids []uint32
	for rows.Next() {
		var uid uint32
		if err := rows.Scan(&uid); err != nil {
			return nil, fmt.Errorf("failed to scan uid: %w", err)
		}
		uids = append(uids, uid)
	}

	return uids, nil
}

// SearchFTSRanked performs a full-text search with relevance ranking
func (s *Searcher) SearchFTSRanked(ctx context.Context, mailboxID uuid.UUID, query string, limit int) ([]uint32, error) {
	sqlQuery := `
		SELECT uid,
			   ts_rank(to_tsvector('english', COALESCE(subject, '') || ' ' || COALESCE(body_text, '')),
			           plainto_tsquery('english', $2)) as rank
		FROM messages
		WHERE mailbox_id = $1
		AND to_tsvector('english', COALESCE(subject, '') || ' ' || COALESCE(body_text, '')) @@ plainto_tsquery('english', $2)
		ORDER BY rank DESC, uid DESC
		LIMIT $3
	`

	rows, err := s.db.Pool.Query(ctx, sqlQuery, mailboxID, query, limit)
	if err != nil {
		return nil, fmt.Errorf("FTS search failed: %w", err)
	}
	defer rows.Close()

	var uids []uint32
	for rows.Next() {
		var uid uint32
		var rank float64
		if err := rows.Scan(&uid, &rank); err != nil {
			return nil, fmt.Errorf("failed to scan uid: %w", err)
		}
		uids = append(uids, uid)
	}

	return uids, nil
}

// buildQuery builds a SQL query from search criteria
func (s *Searcher) buildQuery(mailboxID uuid.UUID, criteria *SearchCriteria) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	argNum := 1

	// Always filter by mailbox
	conditions = append(conditions, fmt.Sprintf("mailbox_id = $%d", argNum))
	args = append(args, mailboxID)
	argNum++

	// Build conditions from criteria
	if criteria != nil {
		s.addCriteriaConditions(criteria, &conditions, &args, &argNum)
	}

	query := fmt.Sprintf(`
		SELECT uid FROM messages
		WHERE %s
		ORDER BY uid
	`, strings.Join(conditions, " AND "))

	return query, args
}

// addCriteriaConditions adds conditions for search criteria
func (s *Searcher) addCriteriaConditions(criteria *SearchCriteria, conditions *[]string, args *[]interface{}, argNum *int) {
	// Flag conditions
	if criteria.Answered {
		*conditions = append(*conditions, `'\\Answered' = ANY(flags)`)
	}
	if criteria.Unanswered {
		*conditions = append(*conditions, `NOT ('\\Answered' = ANY(flags))`)
	}
	if criteria.Deleted {
		*conditions = append(*conditions, `'\\Deleted' = ANY(flags)`)
	}
	if criteria.Undeleted {
		*conditions = append(*conditions, `NOT ('\\Deleted' = ANY(flags))`)
	}
	if criteria.Draft {
		*conditions = append(*conditions, `'\\Draft' = ANY(flags)`)
	}
	if criteria.Undraft {
		*conditions = append(*conditions, `NOT ('\\Draft' = ANY(flags))`)
	}
	if criteria.Flagged {
		*conditions = append(*conditions, `'\\Flagged' = ANY(flags)`)
	}
	if criteria.Unflagged {
		*conditions = append(*conditions, `NOT ('\\Flagged' = ANY(flags))`)
	}
	if criteria.Seen {
		*conditions = append(*conditions, `'\\Seen' = ANY(flags)`)
	}
	if criteria.Unseen {
		*conditions = append(*conditions, `NOT ('\\Seen' = ANY(flags))`)
	}
	if criteria.Recent {
		*conditions = append(*conditions, `'\\Recent' = ANY(flags)`)
	}
	if criteria.New {
		// New = Recent AND NOT Seen
		*conditions = append(*conditions, `'\\Recent' = ANY(flags)`)
		*conditions = append(*conditions, `NOT ('\\Seen' = ANY(flags))`)
	}

	// Internal date conditions
	if criteria.Before != nil {
		*conditions = append(*conditions, fmt.Sprintf("internal_date < $%d", *argNum))
		*args = append(*args, *criteria.Before)
		*argNum++
	}
	if criteria.On != nil {
		// On means the same day
		startOfDay := time.Date(criteria.On.Year(), criteria.On.Month(), criteria.On.Day(), 0, 0, 0, 0, criteria.On.Location())
		endOfDay := startOfDay.Add(24 * time.Hour)
		*conditions = append(*conditions, fmt.Sprintf("internal_date >= $%d AND internal_date < $%d", *argNum, *argNum+1))
		*args = append(*args, startOfDay, endOfDay)
		*argNum += 2
	}
	if criteria.Since != nil {
		*conditions = append(*conditions, fmt.Sprintf("internal_date >= $%d", *argNum))
		*args = append(*args, *criteria.Since)
		*argNum++
	}

	// Sent date conditions (Date header)
	if criteria.SentBefore != nil {
		*conditions = append(*conditions, fmt.Sprintf("date < $%d", *argNum))
		*args = append(*args, *criteria.SentBefore)
		*argNum++
	}
	if criteria.SentOn != nil {
		startOfDay := time.Date(criteria.SentOn.Year(), criteria.SentOn.Month(), criteria.SentOn.Day(), 0, 0, 0, 0, criteria.SentOn.Location())
		endOfDay := startOfDay.Add(24 * time.Hour)
		*conditions = append(*conditions, fmt.Sprintf("date >= $%d AND date < $%d", *argNum, *argNum+1))
		*args = append(*args, startOfDay, endOfDay)
		*argNum += 2
	}
	if criteria.SentSince != nil {
		*conditions = append(*conditions, fmt.Sprintf("date >= $%d", *argNum))
		*args = append(*args, *criteria.SentSince)
		*argNum++
	}

	// Size conditions
	if criteria.Larger > 0 {
		*conditions = append(*conditions, fmt.Sprintf("size > $%d", *argNum))
		*args = append(*args, criteria.Larger)
		*argNum++
	}
	if criteria.Smaller > 0 {
		*conditions = append(*conditions, fmt.Sprintf("size < $%d", *argNum))
		*args = append(*args, criteria.Smaller)
		*argNum++
	}

	// Header conditions
	if criteria.From != "" {
		*conditions = append(*conditions, fmt.Sprintf("from_address ILIKE $%d", *argNum))
		*args = append(*args, "%"+criteria.From+"%")
		*argNum++
	}
	if criteria.To != "" {
		*conditions = append(*conditions, fmt.Sprintf("array_to_string(to_addresses, ',') ILIKE $%d", *argNum))
		*args = append(*args, "%"+criteria.To+"%")
		*argNum++
	}
	if criteria.Cc != "" {
		*conditions = append(*conditions, fmt.Sprintf("array_to_string(cc_addresses, ',') ILIKE $%d", *argNum))
		*args = append(*args, "%"+criteria.Cc+"%")
		*argNum++
	}
	if criteria.Subject != "" {
		*conditions = append(*conditions, fmt.Sprintf("subject ILIKE $%d", *argNum))
		*args = append(*args, "%"+criteria.Subject+"%")
		*argNum++
	}

	// Generic header search
	for header, value := range criteria.Header {
		*conditions = append(*conditions, fmt.Sprintf("headers_json->>$%d ILIKE $%d", *argNum, *argNum+1))
		*args = append(*args, header, "%"+value+"%")
		*argNum += 2
	}

	// Body search (full-text)
	if criteria.Body != "" {
		*conditions = append(*conditions, fmt.Sprintf(
			"to_tsvector('english', COALESCE(body_text, '')) @@ plainto_tsquery('english', $%d)", *argNum))
		*args = append(*args, criteria.Body)
		*argNum++
	}

	// Text search (headers + body)
	if criteria.Text != "" {
		*conditions = append(*conditions, fmt.Sprintf(
			"to_tsvector('english', COALESCE(subject, '') || ' ' || COALESCE(from_address, '') || ' ' || COALESCE(body_text, '')) @@ plainto_tsquery('english', $%d)", *argNum))
		*args = append(*args, criteria.Text)
		*argNum++
	}

	// UID set
	if len(criteria.UIDs) > 0 {
		placeholders := make([]string, len(criteria.UIDs))
		for i, uid := range criteria.UIDs {
			placeholders[i] = fmt.Sprintf("$%d", *argNum)
			*args = append(*args, uid)
			*argNum++
		}
		*conditions = append(*conditions, fmt.Sprintf("uid IN (%s)", strings.Join(placeholders, ", ")))
	}

	// NOT condition
	if criteria.Not != nil {
		var notConditions []string
		s.addCriteriaConditions(criteria.Not, &notConditions, args, argNum)
		if len(notConditions) > 0 {
			*conditions = append(*conditions, fmt.Sprintf("NOT (%s)", strings.Join(notConditions, " AND ")))
		}
	}

	// OR conditions
	if len(criteria.Or) > 0 {
		var orParts []string
		for _, orCriteria := range criteria.Or {
			var orConditions []string
			s.addCriteriaConditions(orCriteria, &orConditions, args, argNum)
			if len(orConditions) > 0 {
				orParts = append(orParts, "("+strings.Join(orConditions, " AND ")+")")
			}
		}
		if len(orParts) > 0 {
			*conditions = append(*conditions, "("+strings.Join(orParts, " OR ")+")")
		}
	}
}

// CountMessages counts messages matching criteria
func (s *Searcher) CountMessages(ctx context.Context, mailboxID uuid.UUID, criteria *SearchCriteria) (int, error) {
	query, args := s.buildCountQuery(mailboxID, criteria)

	var count int
	err := s.db.Pool.QueryRow(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count failed: %w", err)
	}

	return count, nil
}

// buildCountQuery builds a count query from search criteria
func (s *Searcher) buildCountQuery(mailboxID uuid.UUID, criteria *SearchCriteria) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	argNum := 1

	conditions = append(conditions, fmt.Sprintf("mailbox_id = $%d", argNum))
	args = append(args, mailboxID)
	argNum++

	if criteria != nil {
		s.addCriteriaConditions(criteria, &conditions, &args, &argNum)
	}

	query := fmt.Sprintf(`
		SELECT COUNT(*) FROM messages
		WHERE %s
	`, strings.Join(conditions, " AND "))

	return query, args
}

// GetUIDs returns all UIDs in a mailbox
func (s *Searcher) GetUIDs(ctx context.Context, mailboxID uuid.UUID) ([]uint32, error) {
	query := `SELECT uid FROM messages WHERE mailbox_id = $1 ORDER BY uid`

	rows, err := s.db.Pool.Query(ctx, query, mailboxID)
	if err != nil {
		return nil, fmt.Errorf("failed to get UIDs: %w", err)
	}
	defer rows.Close()

	var uids []uint32
	for rows.Next() {
		var uid uint32
		if err := rows.Scan(&uid); err != nil {
			return nil, err
		}
		uids = append(uids, uid)
	}

	return uids, nil
}

// GetUIDRange returns UIDs within a range
func (s *Searcher) GetUIDRange(ctx context.Context, mailboxID uuid.UUID, start, end uint32) ([]uint32, error) {
	query := `SELECT uid FROM messages WHERE mailbox_id = $1 AND uid >= $2 AND uid <= $3 ORDER BY uid`

	rows, err := s.db.Pool.Query(ctx, query, mailboxID, start, end)
	if err != nil {
		return nil, fmt.Errorf("failed to get UID range: %w", err)
	}
	defer rows.Close()

	var uids []uint32
	for rows.Next() {
		var uid uint32
		if err := rows.Scan(&uid); err != nil {
			return nil, err
		}
		uids = append(uids, uid)
	}

	return uids, nil
}

// GetMaxUID returns the maximum UID in a mailbox
func (s *Searcher) GetMaxUID(ctx context.Context, mailboxID uuid.UUID) (uint32, error) {
	query := `SELECT COALESCE(MAX(uid), 0) FROM messages WHERE mailbox_id = $1`

	var maxUID uint32
	err := s.db.Pool.QueryRow(ctx, query, mailboxID).Scan(&maxUID)
	if err != nil {
		return 0, fmt.Errorf("failed to get max UID: %w", err)
	}

	return maxUID, nil
}

// GetMinUID returns the minimum UID in a mailbox
func (s *Searcher) GetMinUID(ctx context.Context, mailboxID uuid.UUID) (uint32, error) {
	query := `SELECT COALESCE(MIN(uid), 0) FROM messages WHERE mailbox_id = $1`

	var minUID uint32
	err := s.db.Pool.QueryRow(ctx, query, mailboxID).Scan(&minUID)
	if err != nil {
		return 0, fmt.Errorf("failed to get min UID: %w", err)
	}

	return minUID, nil
}
