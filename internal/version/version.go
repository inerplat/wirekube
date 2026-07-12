package version

type Info struct {
	Version      string `json:"version"`
	Commit       string `json:"commit"`
	BuildDate    string `json:"buildDate"`
	DefaultImage string `json:"defaultImage,omitempty"`
}

var (
	Version      = "dev"
	Commit       = "unknown"
	BuildDate    = "unknown"
	DefaultImage = ""
)

func Current() Info {
	return Info{
		Version:      Version,
		Commit:       Commit,
		BuildDate:    BuildDate,
		DefaultImage: DefaultImage,
	}
}
