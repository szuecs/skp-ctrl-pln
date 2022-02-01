package fabric

import (
	"regexp"

	"github.com/zalando/skipper/eskip"
	"github.com/zalando/skipper/predicates"
)

var (
	slash        = `/`
	star         = `\*`
	curlyOpen    = `{`
	curlyClose   = `}`
	end          = `$`
	wildcardName = `(?P<name>[\w-]+?)`
	repls        = []struct {
		match *regexp.Regexp
		repl  string
	}{
		{regexp.MustCompile(slash + star + wildcardName + slash), `/:$name/`},
		{regexp.MustCompile(slash + star + wildcardName + end), `/:$name`},
		{regexp.MustCompile(curlyOpen + wildcardName + curlyClose), `:$name`},
		{regexp.MustCompile(slash + star + slash), `/:id/`},
		{regexp.MustCompile(slash + star + end), `/:id`},
	}
)

// fabricPathToPredicate takes a Fabric path string and transforms it an equivalent Skipper Path* predicate
func fabricPathToPredicate(fp string) *eskip.Predicate {
	if fp == "/**" {
		return &eskip.Predicate{Name: predicates.PathSubtreeName, Args: []interface{}{"/"}}
	}

	for _, repl := range repls {
		fp = repl.match.ReplaceAllString(fp, repl.repl)
	}

	return &eskip.Predicate{
		Name: predicates.PathName,
		Args: []interface{}{fp},
	}
}
