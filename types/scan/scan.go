package scan

type URLInfo struct {
	Stable              bool
	CanaryCount         int
	FoundParameters     []string
	PotentialParameters map[string]string
	MaxParams           int
	CanaryValue         string
	NumberOfCheckedURLs int
}

type ScanResults map[string]*URLInfo

type Scan struct {
	ScanResults ScanResults
	WordList    []string
	JsonResults JsonResults
}

type JsonResult struct {
	Params []Param `json:"params"`
}

type Param struct {
	Method string   `json:"method"`
	Names  []string `json:"names"`
}

type JsonResults map[string]JsonResult

func (s *Scan) FillDefaults() {
	s.ScanResults = make(ScanResults)
	s.JsonResults = make(JsonResults)
}
