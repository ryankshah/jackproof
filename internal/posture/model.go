package posture

import (
	"path"
	"sort"
	"strings"

	"github.com/ryankshah/jackproof/internal/config"
	"github.com/ryankshah/jackproof/internal/finding"
	"github.com/ryankshah/jackproof/internal/scan/iac/terraform"
)

type Source struct {
	Path string
	Data []byte
}

type Location struct {
	Path string
	Line int
}

type Statement struct {
	Effect    string
	Actions   []string
	Resources []string
	Location  Location
}

type Grant struct {
	Cloud       Cloud
	Subject     string
	Identity    string
	Attachment  Location
	Source      Location
	Actions     []string
	Resources   []string
	Environment string
	Admin       bool
	Unattached  bool
	Role        string
	Broad       bool
}

type Control struct {
	Location Location
	Detail   string
}

type Budget struct {
	Location Location
	Services []string
}

type Usage struct {
	Service  string
	Location Location
}

type Infra struct {
	Grants     []Grant
	Usage      []Usage
	Guardrails map[Cloud][]Control
	Logging    map[Cloud][]Control
	LoggingOff map[Cloud][]Control
	Budgets    map[Cloud][]Budget
	Quotas     map[Cloud][]Control
	Anchors    map[Cloud]Location
	Accounts   []Account
	Coverage   finding.Coverage
}

type Account struct {
	Address     string
	Location    Location
	Environment string
	Monitored   bool
	Limited     bool
	Deployments []Location
}

func newInfra() *Infra {
	return &Infra{
		Guardrails: make(map[Cloud][]Control),
		Logging:    make(map[Cloud][]Control),
		LoggingOff: make(map[Cloud][]Control),
		Budgets:    make(map[Cloud][]Budget),
		Quotas:     make(map[Cloud][]Control),
		Anchors:    make(map[Cloud]Location),
	}
}

type extractor struct {
	cfg       *config.Config
	knowledge *Knowledge
	infra     *Infra
	skipped   int
}

func Extract(sources []Source, cfg *config.Config, knowledge *Knowledge) *Infra {
	x := &extractor{cfg: cfg, knowledge: knowledge, infra: newInfra()}
	byDirectory := make(map[string][]Source)
	for _, source := range sources {
		if strings.HasSuffix(source.Path, ".tf") || strings.HasSuffix(source.Path, ".tfvars") {
			directory := path.Dir(source.Path)
			byDirectory[directory] = append(byDirectory[directory], source)
		}
	}
	directories := make([]string, 0, len(byDirectory))
	for directory := range byDirectory {
		directories = append(directories, directory)
	}
	sort.Strings(directories)
	for _, directory := range directories {
		module := terraform.NewModule(directory)
		for _, source := range byDirectory[directory] {
			if err := module.AddFile(source.Path, source.Data); err != nil {
				x.infra.Coverage.AddSkipped(source.Path, "terraform not analysed: "+err.Error())
				continue
			}
			x.infra.Coverage.AddScanned("terraform")
		}
		x.aws(module)
		x.gcp(module)
		x.azure(module)
	}
	if x.skipped > 0 {
		x.infra.Coverage.AddSkipped("(policy statements)", "statements that use NotAction or NotResource were not evaluated")
	}
	return x.infra
}

func (x *extractor) environmentFor(location Location) string {
	return x.cfg.EnvironmentForPath(location.Path)
}

func (x *extractor) anchor(cloud Cloud, location Location) {
	if _, exists := x.infra.Anchors[cloud]; !exists {
		x.infra.Anchors[cloud] = location
	}
}

func blockLocation(block *terraform.Block) Location {
	return Location{Path: block.Path, Line: block.Line}
}

func attributeLocation(block *terraform.Block, attribute *terraform.Attribute) Location {
	return Location{Path: block.Path, Line: attribute.Line}
}

func (x *extractor) addGrant(grant Grant) {
	grant.Environment = x.environmentFor(grant.Attachment)
	x.infra.Grants = append(x.infra.Grants, grant)
}
