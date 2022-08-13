package scan

type URLInfo struct {
	Stable              bool
	CanaryCount         int
	ContentType         string
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

func New() *Scan {
	s := Scan{
		ScanResults: make(ScanResults),
		JsonResults: make(JsonResults),
	}
	return &s
}

type JsonResult struct {
	Params []Param `json:"params"`
}

type Param struct {
	Method string   `json:"method"`
	Names  []string `json:"names"`
}

type JsonResults map[string]JsonResult
