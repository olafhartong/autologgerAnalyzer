package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"sort"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const (
	baseAutologgerPath = `SYSTEM\CurrentControlSet\Control\WMI\Autologger`
)

type ETWProvider struct {
	GUID       string
	Name       string
	HasFilters bool
	EventIDs   []int
	Enabled    bool
}

type AutologgerConfig struct {
	Name           string
	Age            uint64
	BufferSize     uint64
	ClockType      uint64
	FlushTimer     uint64
	GUID           string
	LogFileMode    uint64
	MaximumBuffers uint64
	MinimumBuffers uint64
	Start          uint64
	Status         uint64
}

func main() {
	var autologgerName string
	var listMode bool

	flag.StringVar(&autologgerName, "autologger", "", "Name of the autologger to analyze (required)")
	flag.BoolVar(&listMode, "list", false, "List all available autologgers")
	flag.Parse()

	if listMode {
		listAutologgers()
		return
	}

	if autologgerName == "" {
		fmt.Println("Error: autologger name is required")
		fmt.Println("Usage:")
		fmt.Println("  -list                    List all available autologgers")
		fmt.Println("  -autologger <name>       Analyze specific autologger")
		fmt.Println("\nExample:")
		fmt.Println("  go run . -list")
		fmt.Println("  go run . -autologger DefenderApiLogger")
		return
	}

	// Show autologger configuration
	config, err := getAutologgerConfig(autologgerName)
	if err != nil {
		log.Fatalf("Error reading autologger config: %v", err)
	}

	displayAutologgerConfig(config)

	// Show ETW providers
	providers, err := getETWProviders(autologgerName)
	if err != nil {
		log.Fatalf("Error reading ETW providers: %v", err)
	}

	displayETWProviders(providers, autologgerName)
}

func listAutologgers() {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, baseAutologgerPath, registry.READ)
	if err != nil {
		log.Fatalf("Failed to open autologger registry key: %v", err)
	}
	defer key.Close()

	autologgers, err := key.ReadSubKeyNames(-1)
	if err != nil {
		log.Fatalf("Failed to read autologger names: %v", err)
	}

	fmt.Printf("Available Autologgers (%d found):\n", len(autologgers))
	fmt.Println(strings.Repeat("=", 50))

	sort.Strings(autologgers)
	for _, name := range autologgers {
		fmt.Printf("- %s\n", name)
	}
}

func getAutologgerConfig(autologgerName string) (*AutologgerConfig, error) {
	autologgerPath := baseAutologgerPath + `\` + autologgerName
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, autologgerPath, registry.READ)
	if err != nil {
		return nil, fmt.Errorf("failed to open autologger key: %v", err)
	}
	defer key.Close()
	config := &AutologgerConfig{Name: autologgerName}

	if val, _, err := key.GetIntegerValue("Age"); err == nil {
		config.Age = val
	}
	if val, _, err := key.GetIntegerValue("BufferSize"); err == nil {
		config.BufferSize = val
	}
	if val, _, err := key.GetIntegerValue("ClockType"); err == nil {
		config.ClockType = val
	}
	if val, _, err := key.GetIntegerValue("FlushTimer"); err == nil {
		config.FlushTimer = val
	}
	if val, _, err := key.GetStringValue("GUID"); err == nil {
		config.GUID = val
	}
	if val, _, err := key.GetIntegerValue("LogFileMode"); err == nil {
		config.LogFileMode = val
	}
	if val, _, err := key.GetIntegerValue("MaximumBuffers"); err == nil {
		config.MaximumBuffers = val
	}
	if val, _, err := key.GetIntegerValue("MinimumBuffers"); err == nil {
		config.MinimumBuffers = val
	}
	if val, _, err := key.GetIntegerValue("Start"); err == nil {
		config.Start = val
	}
	if val, _, err := key.GetIntegerValue("Status"); err == nil {
		config.Status = val
	}

	return config, nil
}

func displayAutologgerConfig(config *AutologgerConfig) {
	fmt.Printf("Autologger Configuration: %s\n", config.Name)
	fmt.Println(strings.Repeat("=", 60))

	fmt.Printf("| %-20s | %-15s | %-20s |\n", "Property", "Type", "Value")
	fmt.Printf("|%s|%s|%s|\n",
		strings.Repeat("-", 22),
		strings.Repeat("-", 17),
		strings.Repeat("-", 22))

	fmt.Printf("| %-20s | %-15s | %-20d |\n", "Age", "REG_DWORD", config.Age)
	fmt.Printf("| %-20s | %-15s | %-20d |\n", "BufferSize", "REG_DWORD", config.BufferSize)
	fmt.Printf("| %-20s | %-15s | %-20d |\n", "ClockType", "REG_DWORD", config.ClockType)
	fmt.Printf("| %-20s | %-15s | %-20d |\n", "FlushTimer", "REG_DWORD", config.FlushTimer)
	fmt.Printf("| %-20s | %-15s | %-20s |\n", "GUID", "REG_SZ", config.GUID)
	fmt.Printf("| %-20s | %-15s | 0x%-18X |\n", "LogFileMode", "REG_DWORD", config.LogFileMode)
	fmt.Printf("| %-20s | %-15s | %-20d |\n", "MaximumBuffers", "REG_DWORD", config.MaximumBuffers)
	fmt.Printf("| %-20s | %-15s | %-20d |\n", "MinimumBuffers", "REG_DWORD", config.MinimumBuffers)
	fmt.Printf("| %-20s | %-15s | %-20d |\n", "Start", "REG_DWORD", config.Start)
	fmt.Printf("| %-20s | %-15s | %-20d |\n", "Status", "REG_DWORD", config.Status)

	fmt.Printf("\nConfiguration Details:\n")
	fmt.Printf("- Start: %s\n", getStartStatus(config.Start))
	fmt.Printf("- Status: %s\n", getStatusDescription(config.Status))
	fmt.Printf("- LogFileMode: %s\n", getLogFileModeDescription(config.LogFileMode))
	fmt.Println()
}

func getStartStatus(start uint64) string {
	switch start {
	case 0:
		return "Disabled (0)"
	case 1:
		return "Enabled (1)"
	default:
		return fmt.Sprintf("Unknown (%d)", start)
	}
}

func getStatusDescription(status uint64) string {
	switch status {
	case 0:
		return "Stopped (0)"
	case 1:
		return "Running (1)"
	default:
		return fmt.Sprintf("Unknown (%d)", status)
	}
}

func getLogFileModeDescription(mode uint64) string {
	modes := []string{}

	if mode&0x00000001 != 0 {
		modes = append(modes, "FILE_MODE_WRITE")
	}
	if mode&0x00000002 != 0 {
		modes = append(modes, "FILE_MODE_APPEND")
	}
	if mode&0x00000004 != 0 {
		modes = append(modes, "FILE_MODE_CIRCULAR")
	}
	if mode&0x00000008 != 0 {
		modes = append(modes, "FILE_MODE_SEQUENTIAL")
	}
	if mode&0x00000020 != 0 {
		modes = append(modes, "FILE_MODE_REAL_TIME")
	}
	if mode&0x00000080 != 0 {
		modes = append(modes, "FILE_MODE_NEWFILE")
	}
	if mode&0x00000100 != 0 {
		modes = append(modes, "FILE_MODE_DELAY_OPEN_FILE")
	}
	if mode&0x00000200 != 0 {
		modes = append(modes, "FILE_MODE_BUFFERING")
	}
	if mode&0x00000400 != 0 {
		modes = append(modes, "FILE_MODE_PRIVATE_LOGGER")
	}
	if mode&0x00000800 != 0 {
		modes = append(modes, "FILE_MODE_ADD_HEADER")
	}
	if mode&0x00001000 != 0 {
		modes = append(modes, "FILE_MODE_USE_KBYTES_FOR_SIZE")
	}
	if mode&0x00002000 != 0 {
		modes = append(modes, "FILE_MODE_USE_GLOBAL_SEQUENCE")
	}
	if mode&0x00004000 != 0 {
		modes = append(modes, "FILE_MODE_USE_LOCAL_SEQUENCE")
	}
	if mode&0x00008000 != 0 {
		modes = append(modes, "FILE_MODE_RELOG")
	}
	if mode&0x00010000 != 0 {
		modes = append(modes, "FILE_MODE_PRIVATE_IN_PROC")
	}
	if mode&0x00020000 != 0 {
		modes = append(modes, "FILE_MODE_RESERVED")
	}
	if mode&0x00040000 != 0 {
		modes = append(modes, "FILE_MODE_USE_PAGED_MEMORY")
	}
	if mode&0x00080000 != 0 {
		modes = append(modes, "FILE_MODE_CREATE_INPROC")
	}
	if mode&0x00100000 != 0 {
		modes = append(modes, "FILE_MODE_INDEPENDENT_SESSION")
	}
	if mode&0x00200000 != 0 {
		modes = append(modes, "FILE_MODE_NO_PER_PROCESSOR_BUFFERING")
	}
	if mode&0x00400000 != 0 {
		modes = append(modes, "FILE_MODE_BLOCKING")
	}
	if mode&0x00800000 != 0 {
		modes = append(modes, "FILE_MODE_SYSTEM_LOGGER")
	}
	if mode&0x01000000 != 0 {
		modes = append(modes, "FILE_MODE_ADDTO_TRIAGE_DUMP")
	}
	if mode&0x02000000 != 0 {
		modes = append(modes, "FILE_MODE_STOP_ON_HYBRID_SHUTDOWN")
	}
	if mode&0x04000000 != 0 {
		modes = append(modes, "FILE_MODE_PERSIST_ON_HYBRID_SHUTDOWN")
	}
	if mode&0x08000000 != 0 {
		modes = append(modes, "FILE_MODE_USE_CPU_CYCLE")
	}
	if mode&0x10000000 != 0 {
		modes = append(modes, "FILE_MODE_FILE_GENERIC")
	}
	if mode&0x20000000 != 0 {
		modes = append(modes, "FILE_MODE_HARD_DISABLE")
	}

	if len(modes) == 0 {
		return fmt.Sprintf("0x%08X (No flags set)", mode)
	}

	return fmt.Sprintf("0x%08X (%s)", mode, strings.Join(modes, " | "))
}

func displayETWProviders(providers []ETWProvider, autologgerName string) {
	fmt.Printf("ETW Providers under %s (%d found):\n\n", autologgerName, len(providers))

	fmt.Printf("| %-40s | %-35s | %-8s | %-20s |\n", "GUID", "Provider Name", "Enabled", "Event IDs")
	fmt.Printf("|%s|%s|%s|%s|\n",
		strings.Repeat("-", 42),
		strings.Repeat("-", 37),
		strings.Repeat("-", 10),
		strings.Repeat("-", 22))

	for _, provider := range providers {
		enabledStr := "No"
		if provider.Enabled {
			enabledStr = "Yes"
		}

		eventIDsStr := "No Filters"
		if provider.HasFilters {
			if len(provider.EventIDs) > 0 {
				eventIDsStr = fmt.Sprintf("%v", provider.EventIDs)
				if len(eventIDsStr) > 20 {
					eventIDsStr = eventIDsStr[:17] + "..."
				}
			} else {
				eventIDsStr = "No Event IDs"
			}
		}

		fmt.Printf("| %-40s | %-35s | %-8s | %-20s |\n",
			provider.GUID,
			truncateString(provider.Name, 35),
			enabledStr,
			eventIDsStr)
	}
	fmt.Printf("\n\nDetailed Event IDs:\n")
	fmt.Println(strings.Repeat("=", 80))

	for _, provider := range providers {
		if provider.HasFilters && len(provider.EventIDs) > 0 {
			fmt.Printf("\n%s (%s):\n", provider.Name, provider.GUID)
			fmt.Printf("Event IDs: %v\n", provider.EventIDs)
		}
	}
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func getETWProviders(autologgerName string) ([]ETWProvider, error) {
	autologgerPath := baseAutologgerPath + `\` + autologgerName

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, autologgerPath, registry.READ)
	if err != nil {
		return nil, fmt.Errorf("failed to open registry key: %v", err)
	}
	defer key.Close()
	subkeyNames, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("failed to read subkey names: %v", err)
	}

	var providers []ETWProvider

	for _, guid := range subkeyNames {
		provider := ETWProvider{
			GUID: guid,
			Name: resolveProviderName(guid),
		}

		eventIDs, hasFilters, enabled := getEventIDsFromFilters(key, guid)
		provider.HasFilters = hasFilters
		provider.EventIDs = eventIDs
		provider.Enabled = enabled

		providers = append(providers, provider)
	}
	sort.Slice(providers, func(i, j int) bool {
		return providers[i].GUID < providers[j].GUID
	})

	return providers, nil
}

func getEventIDsFromFilters(parentKey registry.Key, providerGUID string) ([]int, bool, bool) {
	filtersKey, err := registry.OpenKey(parentKey, providerGUID+`\Filters`, registry.READ)
	if err != nil {
		return nil, false, false
	}
	defer filtersKey.Close()

	var eventIDs []int
	enabled := false
	if enabledVal, _, err := filtersKey.GetIntegerValue("Enabled"); err == nil {
		enabled = enabledVal != 0
	}

	if binaryVal, _, err := filtersKey.GetBinaryValue("EventIds"); err == nil {
		eventIDs = parseEventIDsBinary(binaryVal)
	}
	valueNames := []string{"EventId", "Events", "Id"}
	for _, valueName := range valueNames {
		if ids := readEventIDsFromValue(filtersKey, valueName); len(ids) > 0 {
			eventIDs = append(eventIDs, ids...)
		}
	}
	eventIDs = removeDuplicates(eventIDs)
	sort.Ints(eventIDs)

	return eventIDs, true, enabled
}

func parseEventIDsBinary(data []byte) []int {
	var eventIDs []int

	for i := 0; i+1 < len(data); i += 2 {
		eventID := binary.LittleEndian.Uint16(data[i : i+2])
		if eventID > 0 && eventID < 65535 {
			eventIDs = append(eventIDs, int(eventID))
		}
	}

	if len(eventIDs) == 0 {
		for i := 0; i+3 < len(data); i += 4 {
			eventID := binary.LittleEndian.Uint32(data[i : i+4])
			if eventID > 0 && eventID < 65535 {
				eventIDs = append(eventIDs, int(eventID))
			}
		}
	}

	return eventIDs
}

func readEventIDsFromValue(key registry.Key, valueName string) []int {
	var eventIDs []int

	if dwordVal, _, err := key.GetIntegerValue(valueName); err == nil {
		if dwordVal <= 65535 {
			eventIDs = append(eventIDs, int(dwordVal))
		}
		return eventIDs
	}

	if binaryVal, _, err := key.GetBinaryValue(valueName); err == nil {
		return parseEventIDsBinary(binaryVal)
	}

	return eventIDs
}

func removeDuplicates(slice []int) []int {
	keys := make(map[int]bool)
	var result []int

	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}

	return result
}

func resolveProviderName(guid string) string {
	publishersPath := `SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\` + guid
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, publishersPath, registry.READ)
	if err != nil {
		return resolveFromWMI(guid)
	}
	defer key.Close()

	if name, _, err := key.GetStringValue(""); err == nil && name != "" {
		return name
	}

	if name, _, err := key.GetStringValue("Name"); err == nil && name != "" {
		return name
	}

	if name, _, err := key.GetStringValue("DisplayName"); err == nil && name != "" {
		return name
	}

	return resolveFromWMI(guid)
}

func resolveFromWMI(guid string) string {
	wmiPath := `SYSTEM\CurrentControlSet\Control\WMI\{` + strings.Trim(guid, "{}") + `}`
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, wmiPath, registry.READ)
	if err != nil {
		return "(Unknown Provider)"
	}
	defer key.Close()

	if name, _, err := key.GetStringValue("Description"); err == nil && name != "" {
		return name
	}

	if name, _, err := key.GetStringValue("DisplayName"); err == nil && name != "" {
		return name
	}

	return "(Unknown Provider)"
}
