package shield

import (
	"regexp"
	"regexp/syntax"
	"strings"
	"sync"
	"unicode/utf8"
)

// matcher is a regexp with a literal prefilter. Go's regexp has no DFA, so a case-insensitive alternation of 30
// scanner names costs ~30 µs on a browser User-Agent. Most patterns can only match where one of a few literal
// strings appears; matcher extracts that set from the parsed pattern and runs the regexp only when the (lower-cased)
// input contains one of them. Clean traffic — the common case — then costs a few substring searches.
type matcher struct {
	re   *regexp.Regexp
	lits []string // lower-case; nil = no prefilter (the pattern can match without any literal)
}

func compileMatcher(pat string) (*matcher, error) {
	re, err := regexp.Compile(pat)
	if err != nil {
		return nil, err
	}
	m := &matcher{re: re}
	if ast, err := syntax.Parse(pat, syntax.Perl); err == nil {
		if lits := required(ast.Simplify()); lits != nil {
			ok := true
			for _, l := range lits {
				if len(l) < 2 {
					ok = false // one-letter literals filter nothing
				}
			}
			if ok {
				m.lits = lits
			}
		}
	}
	return m, nil
}

// required returns literals of which every match contains at least one (lower-cased), or nil when there is none.
func required(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		return []string{strings.ToLower(string(re.Rune))}
	case syntax.OpCapture, syntax.OpPlus:
		return required(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return required(re.Sub[0])
		}
	case syntax.OpConcat:
		// Adjacent literals form a longer one; otherwise keep the child whose shortest literal is longest.
		var best []string
		score := func(ls []string) int {
			if ls == nil {
				return -1
			}
			m := 1 << 30
			for _, l := range ls {
				m = min(m, len(l))
			}
			return m
		}
		run := ""
		flush := func() {
			if run != "" && score([]string{run}) > score(best) {
				best = []string{run}
			}
			run = ""
		}
		for _, sub := range re.Sub {
			if sub.Op == syntax.OpLiteral {
				run += strings.ToLower(string(sub.Rune))
				continue
			}
			flush()
			if ls := required(sub); score(ls) > score(best) {
				best = ls
			}
		}
		flush()
		return best
	case syntax.OpAlternate:
		var all []string
		for _, sub := range re.Sub {
			ls := required(sub)
			if ls == nil {
				return nil
			}
			all = append(all, ls...)
		}
		return all
	case syntax.OpCharClass:
		// A small class of single letters in both cases ((?i)x) gives one-letter literals: useless, skip.
	}
	return nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// MatchString runs the prefilter on a lower-cased copy of s.
func (m *matcher) MatchString(s string) bool {
	if m.lits == nil {
		return m.re.MatchString(s)
	}
	return m.matchLower(s, strings.ToLower(s))
}

// matchLower is MatchString when the caller already has strings.ToLower(s).
func (m *matcher) matchLower(s, lower string) bool {
	if m.lits != nil && isASCII(s) { // non-ASCII: case folding is not byte-wise, use the regexp
		hit := false
		for _, l := range m.lits {
			if strings.Contains(lower, l) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	return m.re.MatchString(s)
}

// memo remembers results per User-Agent. A site sees few distinct User-Agents, and everything computed from the UA
// alone (bot identity, UA signals, UA rules) is the same for every request that sends it. Bounded: when full it
// starts over, so a flood of random User-Agents costs memory once, not forever.
type memo[T any] struct {
	mu sync.RWMutex
	m  map[string]T
}

const memoMax, memoKeyMax = 20000, 512

func newMemo[T any]() *memo[T] { return &memo[T]{m: map[string]T{}} }

func (c *memo[T]) get(k string, compute func() T) T {
	if c == nil || len(k) > memoKeyMax {
		return compute()
	}
	c.mu.RLock()
	v, ok := c.m[k]
	c.mu.RUnlock()
	if ok {
		return v
	}
	v = compute()
	c.mu.Lock()
	if len(c.m) >= memoMax {
		c.m = make(map[string]T, memoMax/4)
	}
	c.m[strings.Clone(k)] = v // own the key: do not pin the request's memory
	c.mu.Unlock()
	return v
}
