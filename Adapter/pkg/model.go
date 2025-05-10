package pkg

import "sort"

// ProcessStat represents process execution statistics.
type ProcessStat struct {
	Name       string // Process name
	TotalCount int    // Total number of execve calls
	Executions int    // Number of currently running instances
	ProcessIDs []int  // List of process IDs
}

// ByTotalCount implements sorting by TotalCount in descending order.
type ByTotalCount []ProcessStat

func (a ByTotalCount) Len() int           { return len(a) }
func (a ByTotalCount) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByTotalCount) Less(i, j int) bool { return a[i].TotalCount > a[j].TotalCount }

// SortProcessStats sorts a slice of ProcessStat by TotalCount in descending order.
func SortProcessStats(stats []ProcessStat) {
	sort.Sort(ByTotalCount(stats))
}
