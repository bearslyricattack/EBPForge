package stdout

import (
	"awesomeProject2/pkg"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// ProcessMapOutput parses and formats bpftool output, counting calls per process name
func ProcessMapOutput(output string) (int, int, []pkg.ProcessStat, error) {
	// Clean output by removing unnecessary characters
	cleanOutput := strings.ReplaceAll(output, "------------------------------------------", "")

	// Attempt to parse the output as JSON
	var entries []struct {
		Key   int `json:"key"`
		Value struct {
			Comm  string `json:"comm"`
			Pid   int    `json:"pid"`
			Count int    `json:"count"`
		} `json:"value"`
	}

	err := json.Unmarshal([]byte(cleanOutput), &entries)
	if err != nil {
		fmt.Printf("JSON parsing error: %v\n", err)
		return 0, 0, nil, err
	}

	// Aggregate call counts by process name
	processStats := make(map[string]struct {
		TotalCount int
		Executions int
		ProcessIDs []int
	})

	for _, entry := range entries {
		procName := entry.Value.Comm
		stats := processStats[procName]
		stats.TotalCount += entry.Value.Count
		stats.Executions++
		stats.ProcessIDs = append(stats.ProcessIDs, entry.Value.Pid)
		processStats[procName] = stats
	}

	// Convert map to sorted slice
	var statsList []pkg.ProcessStat
	for name, stats := range processStats {
		statsList = append(statsList, pkg.ProcessStat{
			Name:       name,
			TotalCount: stats.TotalCount,
			Executions: stats.Executions,
			ProcessIDs: stats.ProcessIDs,
		})
	}

	sort.Slice(statsList, func(i, j int) bool {
		return statsList[i].TotalCount > statsList[j].TotalCount
	})

	// Display results
	fmt.Printf("\n%-20s %-15s %-15s %-20s\n", "Process Name", "Total Calls", "Executions", "PID List (Partial)")
	fmt.Println(strings.Repeat("-", 75))
	for _, stat := range statsList {
		// Display up to 5 PIDs, append "etc" if more exist
		pidDisplay := ""
		if len(stat.ProcessIDs) <= 5 {
			pidDisplay = strings.Join(convertPIDsToStrings(stat.ProcessIDs), ", ")
		} else {
			pidDisplay = strings.Join(convertPIDsToStrings(stat.ProcessIDs[:5]), ", ") + fmt.Sprintf(" etc. (%d total)", len(stat.ProcessIDs))
		}

		fmt.Printf("%-20s %-15d %-15d %-20s\n",
			stat.Name, stat.TotalCount, stat.Executions, pidDisplay)
	}

	totalCalls := SumTotalCounts(statsList)
	fmt.Printf("\nTotal unique processes: %d, Total calls: %d\n", len(statsList), totalCalls)
	return len(statsList), totalCalls, statsList, nil
}

// SumTotalCounts calculates the total number of calls across all processes
func SumTotalCounts(stats []pkg.ProcessStat) int {
	total := 0
	for _, stat := range stats {
		total += stat.TotalCount
	}
	return total
}

// convertPIDsToStrings converts a slice of PIDs to a slice of strings
func convertPIDsToStrings(pids []int) []string {
	strPIDs := make([]string, len(pids))
	for i, pid := range pids {
		strPIDs[i] = fmt.Sprintf("%d", pid)
	}
	return strPIDs
}
