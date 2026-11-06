// OCronGen — Cron Builder/Validator/Explainer
// Part of the OWL security suite.  Author: khaled.s.haddad   Site: owlsec.org
// Language: Go (stdlib only, CGO disabled, static single-file build).
//
// OCronGen is a professional, offline-first Cron Builder/Validator/Explainer with an interactive cyan
// TUI and a full CLI (flag-based) supporting txt|md|json|csv|sarif exports, MITRE
// ATT&CK tagging on findings where meaningful, and A+..F posture grading.

package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	APPNAME = "OCronGen"
	SUITE   = "Owl Cron Suite"
	TAGLINE = "Cron Builder/Validator/Explainer"
	SUBLINE = "Build · Validate · Explain · Next-Runs · Audit · Convert · Grade"
	VERSION = "1.0"
)

const BANNER = `
  ██████╗  ██████╗ ██████╗  ██████╗ ███╗   ██╗ ██████╗ ███████╗███╗   ██╗
 ██╔═══██╗██╔════╝ ██╔══██╗██╔═══██╗████╗  ██║██╔════╝ ██╔════╝████╗  ██║
 ██║   ██║██║      ██████╔╝██║   ██║██╔██╗ ██║██║  ███╗█████╗  ██╔██╗ ██║
 ██║   ██║██║      ██╔══██╗██║   ██║██║╚██╗██║██║   ██║██╔══╝  ██║╚██╗██║
 ╚██████╔╝╚██████╗ ██║  ██║╚██████╔╝██║ ╚████║╚██████╔╝███████╗██║ ╚████║
  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝
`

// ---- OWL UI KIT (cyan "owl" house style) — stdlib only ----
// Shared palette across the OWL suite: CYAN is the primary brand/frame colour;
// red is reserved for errors and CRITICAL/HIGH severities.
const (
	R   = "\033[91m"       // red     — errors / critical
	GRN = "\033[92m"       // green   — success / low
	YLW = "\033[93m"       // yellow  — prompts / warning text
	CY  = "\033[96m"       // cyan    — primary brand & frames
	W   = "\033[97m"       // white   — body text
	B   = "\033[1m"        // bold
	X   = "\033[0m"        // reset
	MG  = "\033[95m"       // magenta — suite name / accents
	BL  = "\033[94m"       // blue    — accents
	DIM = "\033[2m"        // dim     — secondary text
	OR  = "\033[38;5;208m" // orange  — warning markers
	UN  = "\033[4m"        // underline
	GY  = "\033[90m"       // gray    — muted
	DR  = CY               // legacy alias: former "dark red" frame → cyan
)

var noColor = os.Getenv("NO_COLOR") != "" || !isatty()

func isatty() bool { fi, _ := os.Stdout.Stat(); return (fi.Mode() & os.ModeCharDevice) != 0 }
func col(s string, c ...string) string {
	if noColor {
		return s
	}
	return strings.Join(c, "") + s + X
}
func clear()           { fmt.Print("\033[H\033[2J") }
func line(w int)       { fmt.Println(col(strings.Repeat("\u2500", w), CY)) }
func okMsg(s string)   { fmt.Println("  " + col("[\u2714] ", GRN+B) + col(s, W)) }
func errMsg(s string)  { fmt.Println("  " + col("[\u2718] ", R+B) + col(s, R)) }
func warnMsg(s string) { fmt.Println("  " + col("[!] ", OR+B) + col(s, YLW)) }
func info(s string)    { fmt.Println("  " + col("[*] ", CY) + col(s, DIM+W)) }

func banner() {
	fmt.Println(col(BANNER, CY))
	fmt.Println("  " + col(SUITE+"  ", B+MG) + col("v"+VERSION, YLW))
	fmt.Println("  " + col(SUBLINE, W))
	fmt.Println()
	fmt.Println("  " + col("Developer : ", DIM) + col("khaled.s.haddad", CY) +
		col("   |   Website : ", DIM) + col("owlsec.org", CY))
	fmt.Println(col(strings.Repeat("\u2500", 66), CY))
	fmt.Println()
}
func prompt(label string) string {
	fmt.Print("  " + col("[\u00bb] ", YLW) + col(label+": ", W))
	rd := bufio.NewReader(os.Stdin)
	s, _ := rd.ReadString('\n')
	return strings.TrimSpace(s)
}
func pause() {
	fmt.Print(col("\n  [\u21a9] Press Enter to continue...", YLW))
	bufio.NewReader(os.Stdin).ReadString('\n')
}

type menuItem struct {
	key, name, desc, clr string
}

// header prints an ONode-style section header (\u2b21 Title between cyan rules).
func header(title string) {
	fmt.Println()
	fmt.Println(col(strings.Repeat("\u2500", 66), CY))
	fmt.Println("  " + col("\u2b21  "+title, B+CY))
	fmt.Println(col(strings.Repeat("\u2500", 66), CY))
	fmt.Println()
}

// showMenu renders the ONode-style main menu and returns the selection.
func showMenu(title string, items []menuItem) string {
	clear()
	banner()
	fmt.Println("  " + col("\u2b21  "+title, B+CY))
	fmt.Println()
	for _, it := range items {
		fmt.Println("  " + col(pad("["+it.key+"]", 4), it.clr) + "  " +
			col(pad(it.name, 18), W) + col("\u2500 "+it.desc, DIM))
	}
	fmt.Println()
	fmt.Println("  " + col(pad("[H]", 4), YLW+B) + "  " + col(pad("Help & Usage", 18), W) + col("─ How to use, every option, CLI flags & examples", DIM))
	fmt.Println("  " + col(pad("[0]", 4), R) + "  " + col(pad("Exit", 18), W) + col("\u2500 Quit OCronGen", DIM))
	fmt.Println()
	fmt.Println(col(strings.Repeat("\u2500", 66), CY))
	return prompt("Select option")
}
func pad(s string, n int) string {
	if visw(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-visw(s))
}
func visw(s string) int { return len([]rune(s)) }
func table(headers []string, rows [][]string) {
	w := make([]int, len(headers))
	for i, h := range headers {
		w[i] = visw(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < len(w) && visw(c) > w[i] {
				w[i] = visw(c)
			}
		}
	}
	var hb strings.Builder
	for i, h := range headers {
		hb.WriteString(col(pad(h, w[i]), CY+B))
		if i < len(headers)-1 {
			hb.WriteString(col(" \u2502 ", DR))
		}
	}
	fmt.Println("  " + hb.String())
	seg := make([]string, len(w))
	for i := range w {
		seg[i] = strings.Repeat("\u2500", w[i])
	}
	fmt.Println("  " + col(strings.Join(seg, "\u2500\u253c\u2500"), DR))
	for _, r := range rows {
		var rb strings.Builder
		for i := range headers {
			v := ""
			if i < len(r) {
				v = r[i]
			}
			rb.WriteString(col(pad(v, w[i]), W))
			if i < len(headers)-1 {
				rb.WriteString(col(" \u2502 ", DR))
			}
		}
		fmt.Println("  " + rb.String())
	}
}

// ---- shared finding model, grading, and 5-format export engine ----
type Finding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Category    string   `json:"category"`
	ATTCK       []string `json:"attck,omitempty"`
	CWE         string   `json:"cwe,omitempty"`
	Description string   `json:"description"`
	Evidence    string   `json:"evidence,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Location    string   `json:"location,omitempty"`
	Score       float64  `json:"score"`
}

type KV struct {
	K string `json:"key"`
	V string `json:"value"`
}

type Report struct {
	Tool      string    `json:"tool"`
	Tagline   string    `json:"tagline"`
	Version   string    `json:"version"`
	Target    string    `json:"target"`
	Generated string    `json:"generated"`
	Findings  []Finding `json:"findings"`
	Stats     []KV      `json:"stats"`
	Notes     []string  `json:"notes,omitempty"`
	Grade     string    `json:"grade"`
	Score     float64   `json:"score"`
}

var sevOrder = map[string]int{"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

func sevRank(s string) int {
	if v, ok := sevOrder[strings.ToUpper(s)]; ok {
		return v
	}
	return 0
}
func sevColor(s string) string {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return R + B
	case "HIGH":
		return R
	case "MEDIUM":
		return YLW
	case "LOW":
		return GRN
	default:
		return GY
	}
}
func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if sevRank(fs[i].Severity) != sevRank(fs[j].Severity) {
			return sevRank(fs[i].Severity) > sevRank(fs[j].Severity)
		}
		return fs[i].Score > fs[j].Score
	})
}
func gradeFromScore(f float64) string {
	switch {
	case f >= 97:
		return "A+"
	case f >= 93:
		return "A"
	case f >= 90:
		return "A-"
	case f >= 87:
		return "B+"
	case f >= 83:
		return "B"
	case f >= 80:
		return "B-"
	case f >= 77:
		return "C+"
	case f >= 73:
		return "C"
	case f >= 70:
		return "C-"
	case f >= 65:
		return "D+"
	case f >= 60:
		return "D"
	default:
		return "F"
	}
}
func computePosture(fs []Finding) (string, float64) {
	score := 100.0
	for _, f := range fs {
		switch strings.ToUpper(f.Severity) {
		case "CRITICAL":
			score -= 22
		case "HIGH":
			score -= 13
		case "MEDIUM":
			score -= 6
		case "LOW":
			score -= 2.5
		case "INFO":
			score -= 0.3
		}
	}
	if score < 0 {
		score = 0
	}
	return gradeFromScore(score), score
}
func sevCounts(fs []Finding) map[string]int {
	m := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
	for _, f := range fs {
		m[strings.ToUpper(f.Severity)]++
	}
	return m
}
func newReport(target string) *Report {
	return &Report{
		Tool:      APPNAME,
		Tagline:   TAGLINE,
		Version:   VERSION,
		Target:    target,
		Generated: time.Now().Format("2006-01-02 15:04:05 -0700"),
	}
}
func (r *Report) finalize() {
	sortFindings(r.Findings)
	r.Grade, r.Score = computePosture(r.Findings)
}

func jsonEscape(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func exportJSON(r *Report) string {
	r.finalize()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	_ = enc.Encode(r)
	return buf.String()
}

func exportCSV(r *Report) string {
	r.finalize()
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	w.Write([]string{"id", "severity", "score", "category", "title", "attck", "cwe", "location", "description", "remediation"})
	for _, f := range r.Findings {
		w.Write([]string{f.ID, f.Severity, strconv.FormatFloat(f.Score, 'f', 1, 64), f.Category, f.Title, strings.Join(f.ATTCK, " "), f.CWE, f.Location, oneLine(f.Description), oneLine(f.Remediation)})
	}
	w.Flush()
	return buf.String()
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return strings.TrimSpace(s)
}

func exportTXT(r *Report) string {
	r.finalize()
	var b strings.Builder
	bar := strings.Repeat("=", 72)
	b.WriteString(bar + "\n")
	b.WriteString("  " + r.Tool + " — " + r.Tagline + "\n")
	b.WriteString("  Author: khaled.s.haddad    Site: owlsec.org    Version: " + r.Version + "\n")
	b.WriteString(bar + "\n")
	b.WriteString("Target    : " + r.Target + "\n")
	b.WriteString("Generated : " + r.Generated + "\n")
	b.WriteString(fmt.Sprintf("Posture   : %s (%.1f/100)\n", r.Grade, r.Score))
	c := sevCounts(r.Findings)
	b.WriteString(fmt.Sprintf("Findings  : %d  [CRIT %d | HIGH %d | MED %d | LOW %d | INFO %d]\n",
		len(r.Findings), c["CRITICAL"], c["HIGH"], c["MEDIUM"], c["LOW"], c["INFO"]))
	if len(r.Stats) > 0 {
		b.WriteString("\n-- Statistics --\n")
		for _, kv := range r.Stats {
			b.WriteString(fmt.Sprintf("  %-28s : %s\n", kv.K, kv.V))
		}
	}
	if len(r.Findings) > 0 {
		b.WriteString("\n-- Findings --\n")
		for i, f := range r.Findings {
			b.WriteString(fmt.Sprintf("\n[%d] %s  (%s, score %.1f)\n", i+1, f.Title, f.Severity, f.Score))
			b.WriteString("    id         : " + f.ID + "\n")
			b.WriteString("    category   : " + f.Category + "\n")
			if len(f.ATTCK) > 0 {
				b.WriteString("    att&ck     : " + annotateATTCK(f.ATTCK) + "\n")
			}
			if f.CWE != "" {
				b.WriteString("    cwe        : " + f.CWE + "\n")
			}
			if f.Location != "" {
				b.WriteString("    location   : " + f.Location + "\n")
			}
			if f.Description != "" {
				b.WriteString("    detail     : " + f.Description + "\n")
			}
			if f.Evidence != "" {
				b.WriteString("    evidence   : " + oneLine(f.Evidence) + "\n")
			}
			if f.Remediation != "" {
				b.WriteString("    fix        : " + f.Remediation + "\n")
			}
		}
	}
	if len(r.Notes) > 0 {
		b.WriteString("\n-- Notes --\n")
		for _, n := range r.Notes {
			b.WriteString("  * " + n + "\n")
		}
	}
	b.WriteString("\n" + bar + "\n")
	return b.String()
}

func exportMD(r *Report) string {
	r.finalize()
	var b strings.Builder
	b.WriteString("# " + r.Tool + " Report\n\n")
	b.WriteString("*" + r.Tagline + "*\n\n")
	b.WriteString("| Field | Value |\n|---|---|\n")
	b.WriteString("| Target | " + mdEsc(r.Target) + " |\n")
	b.WriteString("| Generated | " + r.Generated + " |\n")
	b.WriteString("| Version | " + r.Version + " |\n")
	b.WriteString(fmt.Sprintf("| Posture | **%s** (%.1f/100) |\n", r.Grade, r.Score))
	c := sevCounts(r.Findings)
	b.WriteString(fmt.Sprintf("| Findings | %d (C%d/H%d/M%d/L%d/I%d) |\n\n",
		len(r.Findings), c["CRITICAL"], c["HIGH"], c["MEDIUM"], c["LOW"], c["INFO"]))
	if len(r.Stats) > 0 {
		b.WriteString("## Statistics\n\n| Metric | Value |\n|---|---|\n")
		for _, kv := range r.Stats {
			b.WriteString("| " + mdEsc(kv.K) + " | " + mdEsc(kv.V) + " |\n")
		}
		b.WriteString("\n")
	}
	if len(r.Findings) > 0 {
		b.WriteString("## Findings\n\n")
		for i, f := range r.Findings {
			b.WriteString(fmt.Sprintf("### %d. %s\n\n", i+1, mdEsc(f.Title)))
			b.WriteString("- **Severity:** " + f.Severity + fmt.Sprintf(" (score %.1f)\n", f.Score))
			b.WriteString("- **ID:** `" + f.ID + "`\n")
			b.WriteString("- **Category:** " + mdEsc(f.Category) + "\n")
			if len(f.ATTCK) > 0 {
				b.WriteString("- **ATT&CK:** " + annotateATTCK(f.ATTCK) + "\n")
			}
			if f.CWE != "" {
				b.WriteString("- **CWE:** " + f.CWE + "\n")
			}
			if f.Location != "" {
				b.WriteString("- **Location:** `" + f.Location + "`\n")
			}
			if f.Description != "" {
				b.WriteString("- **Detail:** " + mdEsc(f.Description) + "\n")
			}
			if f.Evidence != "" {
				b.WriteString("- **Evidence:** `" + oneLine(f.Evidence) + "`\n")
			}
			if f.Remediation != "" {
				b.WriteString("- **Fix:** " + mdEsc(f.Remediation) + "\n")
			}
			b.WriteString("\n")
		}
	}
	if len(r.Notes) > 0 {
		b.WriteString("## Notes\n\n")
		for _, n := range r.Notes {
			b.WriteString("- " + mdEsc(n) + "\n")
		}
	}
	return b.String()
}

func mdEsc(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	return s
}

func sarifLevel(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	case "LOW", "INFO":
		return "note"
	default:
		return "none"
	}
}

func exportSARIF(r *Report) string {
	r.finalize()
	type sarifMsg struct {
		Text string `json:"text"`
	}
	type sarifRule struct {
		ID               string            `json:"id"`
		Name             string            `json:"name"`
		ShortDescription sarifMsg          `json:"shortDescription"`
		FullDescription  sarifMsg          `json:"fullDescription"`
		HelpURI          string            `json:"helpUri,omitempty"`
		Properties       map[string]any    `json:"properties,omitempty"`
		DefaultConfig    map[string]string `json:"defaultConfiguration,omitempty"`
	}
	type sarifArtifact struct {
		URI string `json:"uri"`
	}
	type sarifRegion struct {
		StartLine int `json:"startLine,omitempty"`
	}
	type sarifPhys struct {
		ArtifactLocation sarifArtifact `json:"artifactLocation"`
		Region           *sarifRegion  `json:"region,omitempty"`
	}
	type sarifLoc struct {
		PhysicalLocation sarifPhys `json:"physicalLocation"`
	}
	type sarifResult struct {
		RuleID    string         `json:"ruleId"`
		Level     string         `json:"level"`
		Message   sarifMsg       `json:"message"`
		Locations []sarifLoc     `json:"locations,omitempty"`
		Props     map[string]any `json:"properties,omitempty"`
	}
	type sarifDriver struct {
		Name           string      `json:"name"`
		Version        string      `json:"version"`
		InformationURI string      `json:"informationUri"`
		Rules          []sarifRule `json:"rules"`
	}
	type sarifTool struct {
		Driver sarifDriver `json:"driver"`
	}
	type sarifRun struct {
		Tool    sarifTool     `json:"tool"`
		Results []sarifResult `json:"results"`
	}
	type sarifDoc struct {
		Schema  string     `json:"$schema"`
		Version string     `json:"version"`
		Runs    []sarifRun `json:"runs"`
	}
	ruleSeen := map[string]bool{}
	var rules []sarifRule
	var results []sarifResult
	for _, f := range r.Findings {
		if !ruleSeen[f.ID] {
			ruleSeen[f.ID] = true
			props := map[string]any{"severity": f.Severity, "category": f.Category}
			if len(f.ATTCK) > 0 {
				props["attck"] = f.ATTCK
			}
			if f.CWE != "" {
				props["cwe"] = f.CWE
			}
			rules = append(rules, sarifRule{
				ID:               f.ID,
				Name:             f.Title,
				ShortDescription: sarifMsg{Text: f.Title},
				FullDescription:  sarifMsg{Text: nonEmpty(f.Description, f.Title)},
				HelpURI:          "https://owlsec.org",
				Properties:       props,
				DefaultConfig:    map[string]string{"level": sarifLevel(f.Severity)},
			})
		}
		loc := nonEmpty(f.Location, r.Target)
		res := sarifResult{
			RuleID:  f.ID,
			Level:   sarifLevel(f.Severity),
			Message: sarifMsg{Text: nonEmpty(f.Description, f.Title)},
			Props:   map[string]any{"score": f.Score, "severity": f.Severity},
			Locations: []sarifLoc{{PhysicalLocation: sarifPhys{
				ArtifactLocation: sarifArtifact{URI: loc},
			}}},
		}
		results = append(results, res)
	}
	doc := sarifDoc{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           r.Tool,
				Version:        r.Version,
				InformationURI: "https://owlsec.org",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	_ = enc.Encode(doc)
	return buf.String()
}

func nonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func renderReport(r *Report, format string) string {
	switch strings.ToLower(format) {
	case "json":
		return exportJSON(r)
	case "csv":
		return exportCSV(r)
	case "md", "markdown":
		return exportMD(r)
	case "sarif":
		return exportSARIF(r)
	default:
		return exportTXT(r)
	}
}

func emit(r *Report, format, output string) error {
	content := renderReport(r, format)
	if output == "" || output == "-" {
		fmt.Print(content)
		if !strings.HasSuffix(content, "\n") {
			fmt.Println()
		}
		return nil
	}
	if err := os.WriteFile(output, []byte(content), 0644); err != nil {
		return err
	}
	okMsg("wrote " + format + " report to " + output)
	return nil
}

func showFindingsTUI(r *Report) {
	r.finalize()
	if len(r.Findings) == 0 {
		okMsg("no findings")
		return
	}
	rows := [][]string{}
	for _, f := range r.Findings {
		at := strings.Join(f.ATTCK, ",")
		if at == "" {
			at = "-"
		}
		rows = append(rows, []string{f.ID, f.Severity, fmt.Sprintf("%.1f", f.Score), f.Title, at})
	}
	table([]string{"ID", "SEV", "SCORE", "TITLE", "ATT&CK"}, rows)
	fmt.Println()
	info(fmt.Sprintf("posture grade %s (%.1f/100)", r.Grade, r.Score))
}

// ---- shared utility helpers (hexdump, entropy, histograms, formatting) ----
func hexDump(b []byte) string {
	var sb strings.Builder
	for i := 0; i < len(b); i += 16 {
		sb.WriteString(fmt.Sprintf("%08x  ", i))
		for j := 0; j < 16; j++ {
			if i+j < len(b) {
				sb.WriteString(fmt.Sprintf("%02x ", b[i+j]))
			} else {
				sb.WriteString("   ")
			}
			if j == 7 {
				sb.WriteString(" ")
			}
		}
		sb.WriteString(" |")
		for j := 0; j < 16 && i+j < len(b); j++ {
			c := b[i+j]
			if c >= 32 && c < 127 {
				sb.WriteByte(c)
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteString("|\n")
	}
	return sb.String()
}

func entropyOf(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var freq [256]int
	for _, c := range b {
		freq[c]++
	}
	var h float64
	n := float64(len(b))
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := float64(f) / n
		h -= p * mathLog2(p)
	}
	return h
}

func mathLog2(x float64) float64 { return lnApprox(x) / 0.6931471805599453 }

func lnApprox(x float64) float64 {
	if x <= 0 {
		return 0
	}
	k := 0
	for x > 2 {
		x /= 2
		k++
	}
	for x < 0.5 {
		x *= 2
		k--
	}
	y := (x - 1) / (x + 1)
	y2 := y * y
	sum := 0.0
	term := y
	for i := 1; i <= 19; i += 2 {
		sum += term / float64(i)
		term *= y2
	}
	return 2*sum + float64(k)*0.6931471805599453
}

func humanBytes(n int64) string {
	const u = 1024
	if n < u {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(u), 0
	for x := n / u; x >= u; x /= u {
		div *= u
		exp++
	}
	units := []string{"KB", "MB", "GB", "TB", "PB", "EB"}
	return fmt.Sprintf("%.2f %s", float64(n)/float64(div), units[exp])
}

func commaInt(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	if neg {
		return "-" + string(out)
	}
	return string(out)
}

func asciiBar(frac float64, width int) string {
	if frac < 0 {
		frac = 0
	}
	if frac > 1 {
		frac = 1
	}
	fill := int(frac * float64(width))
	if fill > width {
		fill = width
	}
	return strings.Repeat("\u2588", fill) + strings.Repeat("\u2591", width-fill)
}

func byteHistogram(b []byte) [256]int {
	var h [256]int
	for _, c := range b {
		h[c]++
	}
	return h
}

func truncStr(s string, n int) string {
	if len([]rune(s)) <= n {
		return s
	}
	r := []rune(s)
	if n < 1 {
		return ""
	}
	return string(r[:n-1]) + "\u2026"
}

func minI(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func maxI(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func absI(a int) int {
	if a < 0 {
		return -a
	}
	return a
}
func clampF(x, lo, hi float64) float64 {
	if x < lo {
		return lo
	}
	if x > hi {
		return hi
	}
	return x
}

func kvTable(pairs []KV) {
	rows := [][]string{}
	for _, kv := range pairs {
		rows = append(rows, []string{kv.K, kv.V})
	}
	table([]string{"METRIC", "VALUE"}, rows)
}

func printHelpSection(title string, lines []string) {
	fmt.Println(col("  "+title, CY+B))
	for _, l := range lines {
		fmt.Println("    " + l)
	}
	fmt.Println()
}

func readLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range strings.Split(string(data), "\n") {
		out = append(out, l)
	}
	return out, nil
}

func wrapText(s string, width int) []string {
	words := strings.Fields(s)
	var lines []string
	cur := ""
	for _, w := range words {
		if len(cur)+len(w)+1 > width {
			lines = append(lines, cur)
			cur = w
		} else if cur == "" {
			cur = w
		} else {
			cur += " " + w
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

// atoiSafe parses an int, returning def on error.
func atoiSafe(s string, def int) int {
	s = strings.TrimSpace(s)
	if v, err := strconv.Atoi(s); err == nil {
		return v
	}
	return def
}

// splitCSVLine does minimal CSV field splitting on a single line.
func splitCSVLine(s string) []string {
	var out []string
	var cur strings.Builder
	inq := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			inq = !inq
		case c == ',' && !inq:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	out = append(out, cur.String())
	return out
}

// ---- shared MITRE ATT&CK + CWE reference (used by finding renderers) ----
var attckNames = map[string]string{
	"T1003":     "OS Credential Dumping",
	"T1003.001": "LSASS Memory",
	"T1027":     "Obfuscated Files or Information",
	"T1053":     "Scheduled Task/Job",
	"T1053.003": "Cron",
	"T1059.004": "Unix Shell",
	"T1105":     "Ingress Tool Transfer",
	"T1005":     "Data from Local System",
	"T1016":     "System Network Configuration Discovery",
	"T1018":     "Remote System Discovery",
	"T1021":     "Remote Services",
	"T1021.001": "Remote Desktop Protocol",
	"T1021.002": "SMB/Windows Admin Shares",
	"T1033":     "System Owner/User Discovery",
	"T1036":     "Masquerading",
	"T1040":     "Network Sniffing",
	"T1046":     "Network Service Discovery",
	"T1048":     "Exfiltration Over Alternative Protocol",
	"T1055":     "Process Injection",
	"T1057":     "Process Discovery",
	"T1059":     "Command and Scripting Interpreter",
	"T1068":     "Exploitation for Privilege Escalation",
	"T1070":     "Indicator Removal",
	"T1070.002": "Clear Linux or Mac System Logs",
	"T1071":     "Application Layer Protocol",
	"T1071.001": "Web Protocols",
	"T1071.004": "DNS",
	"T1078":     "Valid Accounts",
	"T1082":     "System Information Discovery",
	"T1083":     "File and Directory Discovery",
	"T1090":     "Proxy",
	"T1095":     "Non-Application Layer Protocol",
	"T1098":     "Account Manipulation",
	"T1110":     "Brute Force",
	"T1110.001": "Password Guessing",
	"T1110.003": "Password Spraying",
	"T1133":     "External Remote Services",
	"T1135":     "Network Share Discovery",
	"T1136":     "Create Account",
	"T1190":     "Exploit Public-Facing Application",
	"T1203":     "Exploitation for Client Execution",
	"T1210":     "Exploitation of Remote Services",
	"T1211":     "Exploitation for Defense Evasion",
	"T1217":     "Browser Information Discovery",
	"T1222":     "File and Directory Permissions Modification",
	"T1222.001": "Windows File and Directory Permissions Modification",
	"T1222.002": "Linux and Mac File and Directory Permissions Modification",
	"T1480":     "Execution Guardrails",
	"T1485":     "Data Destruction",
	"T1486":     "Data Encrypted for Impact",
	"T1489":     "Service Stop",
	"T1498":     "Network Denial of Service",
	"T1499":     "Endpoint Denial of Service",
	"T1518":     "Software Discovery",
	"T1543":     "Create or Modify System Process",
	"T1543.002": "Systemd Service",
	"T1547":     "Boot or Logon Autostart Execution",
	"T1548":     "Abuse Elevation Control Mechanism",
	"T1548.001": "Setuid and Setgid",
	"T1552":     "Unsecured Credentials",
	"T1552.001": "Credentials In Files",
	"T1552.004": "Private Keys",
	"T1553":     "Subvert Trust Controls",
	"T1557":     "Adversary-in-the-Middle",
	"T1557.001": "LLMNR/NBT-NS Poisoning and SMB Relay",
	"T1562":     "Impair Defenses",
	"T1562.001": "Disable or Modify Tools",
	"T1565":     "Data Manipulation",
	"T1565.001": "Stored Data Manipulation",
	"T1570":     "Lateral Tool Transfer",
	"T1571":     "Non-Standard Port",
	"T1572":     "Protocol Tunneling",
	"T1573":     "Encrypted Channel",
	"T1573.001": "Symmetric Cryptography",
	"T1574":     "Hijack Execution Flow",
	"T1589":     "Gather Victim Identity Information",
	"T1590":     "Gather Victim Network Information",
	"T1595":     "Active Scanning",
	"T1599":     "Network Boundary Bridging",
	"T1600":     "Weaken Encryption",
	"T1602":     "Data from Configuration Repository",
	"T1610":     "Deploy Container",
	"T1611":     "Escape to Host",
}

var cweNames = map[string]string{
	"CWE-22":   "Path Traversal",
	"CWE-78":   "OS Command Injection",
	"CWE-79":   "Cross-site Scripting",
	"CWE-89":   "SQL Injection",
	"CWE-200":  "Exposure of Sensitive Information",
	"CWE-209":  "Information Exposure Through an Error Message",
	"CWE-250":  "Execution with Unnecessary Privileges",
	"CWE-269":  "Improper Privilege Management",
	"CWE-276":  "Incorrect Default Permissions",
	"CWE-295":  "Improper Certificate Validation",
	"CWE-306":  "Missing Authentication for Critical Function",
	"CWE-307":  "Improper Restriction of Excessive Authentication Attempts",
	"CWE-311":  "Missing Encryption of Sensitive Data",
	"CWE-312":  "Cleartext Storage of Sensitive Information",
	"CWE-319":  "Cleartext Transmission of Sensitive Information",
	"CWE-326":  "Inadequate Encryption Strength",
	"CWE-327":  "Use of a Broken or Risky Cryptographic Algorithm",
	"CWE-328":  "Use of Weak Hash",
	"CWE-330":  "Use of Insufficiently Random Values",
	"CWE-338":  "Use of Cryptographically Weak PRNG",
	"CWE-426":  "Untrusted Search Path",
	"CWE-494":  "Download of Code Without Integrity Check",
	"CWE-521":  "Weak Password Requirements",
	"CWE-522":  "Insufficiently Protected Credentials",
	"CWE-532":  "Insertion of Sensitive Information into Log File",
	"CWE-601":  "Open Redirect",
	"CWE-732":  "Incorrect Permission Assignment for Critical Resource",
	"CWE-798":  "Use of Hard-coded Credentials",
	"CWE-918":  "Server-Side Request Forgery",
	"CWE-1104": "Use of Unmaintained Third Party Components",
}

func attckName(id string) string {
	if n, ok := attckNames[id]; ok {
		return n
	}
	return id
}

func cweName(id string) string {
	if !strings.HasPrefix(id, "CWE-") {
		id = "CWE-" + id
	}
	if n, ok := cweNames[id]; ok {
		return id + " (" + n + ")"
	}
	return id
}

func annotateATTCK(ids []string) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		if n := attckName(id); n != id {
			parts = append(parts, id+" "+n)
		} else {
			parts = append(parts, id)
		}
	}
	return strings.Join(parts, ", ")
}

// printTechniqueCatalog lists all known ATT&CK techniques referenced by the suite.
func printTechniqueCatalog() {
	var ids []string
	for id := range attckNames {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rows := [][]string{}
	for _, id := range ids {
		rows = append(rows, []string{id, attckNames[id]})
	}
	table([]string{"TECHNIQUE", "NAME"}, rows)
}

// ============================================================================
//  OCronGen — professional cron expression builder, validator, explainer,
//  next-N run calculator (with timezones), @macro expansion, anomaly checks,
//  and schedule risk grading. Supports standard 5-field and extended 6-field
//  (with seconds) expressions plus Quartz specials (L, W, #) when enabled.
// ============================================================================

type fieldKind int

const (
	fkSecond fieldKind = iota
	fkMinute
	fkHour
	fkDom // day of month
	fkMonth
	fkDow // day of week
)

type fieldSpec struct {
	kind     fieldKind
	name     string
	min, max int
	names    map[string]int
}

var (
	monthNames = map[string]int{"JAN": 1, "FEB": 2, "MAR": 3, "APR": 4, "MAY": 5, "JUN": 6, "JUL": 7, "AUG": 8, "SEP": 9, "OCT": 10, "NOV": 11, "DEC": 12}
	dowNames   = map[string]int{"SUN": 0, "MON": 1, "TUE": 2, "WED": 3, "THU": 4, "FRI": 5, "SAT": 6}
)

func specs5() []fieldSpec {
	return []fieldSpec{
		{fkMinute, "minute", 0, 59, nil},
		{fkHour, "hour", 0, 23, nil},
		{fkDom, "day-of-month", 1, 31, nil},
		{fkMonth, "month", 1, 12, monthNames},
		{fkDow, "day-of-week", 0, 7, dowNames}, // 7==0==Sunday
	}
}
func specs6() []fieldSpec {
	return append([]fieldSpec{{fkSecond, "second", 0, 59, nil}}, specs5()...)
}

// CronExpr is a parsed expression.
type CronExpr struct {
	Raw      string
	Fields   []fieldSet // ordered: [sec?] min hour dom month dow
	HasSec   bool
	Macro    string
	Warnings []string
}

type fieldSet struct {
	spec     fieldSpec
	raw      string
	values   []int // expanded discrete values
	any      bool  // true if *
	hash     int   // Quartz #: N#K  (Nth weekday K of month); -1 unused
	last     bool  // Quartz L
	nearestW bool  // Quartz W (nearest weekday)
}

var macros = map[string]string{
	"@yearly":   "0 0 1 1 *",
	"@annually": "0 0 1 1 *",
	"@monthly":  "0 0 1 * *",
	"@weekly":   "0 0 * * 0",
	"@daily":    "0 0 * * *",
	"@midnight": "0 0 * * *",
	"@hourly":   "0 * * * *",
	"@reboot":   "@reboot", // special sentinel
}

func expandMacro(s string) (string, string, bool) {
	key := strings.ToLower(strings.TrimSpace(s))
	if v, ok := macros[key]; ok {
		return v, key, true
	}
	return s, "", false
}

// ParseCron parses a 5- or 6-field cron (or @macro). quartz enables L/W/#.
func ParseCron(expr string, quartz bool) (*CronExpr, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, fmt.Errorf("empty expression")
	}
	raw := expr
	expanded, macro, isMacro := expandMacro(expr)
	if isMacro && expanded == "@reboot" {
		return &CronExpr{Raw: raw, Macro: macro}, nil
	}
	expr = expanded
	parts := strings.Fields(expr)
	var specs []fieldSpec
	switch len(parts) {
	case 5:
		specs = specs5()
	case 6:
		specs = specs6()
	default:
		return nil, fmt.Errorf("expected 5 or 6 fields (got %d)", len(parts))
	}
	ce := &CronExpr{Raw: raw, HasSec: len(parts) == 6, Macro: macro}
	for i, p := range parts {
		fs, warns, err := parseField(p, specs[i], quartz)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", specs[i].name, err)
		}
		ce.Fields = append(ce.Fields, fs)
		ce.Warnings = append(ce.Warnings, warns...)
	}
	// day-of-week 7 -> 0 normalisation already done in parseField
	ce.Warnings = append(ce.Warnings, anomalyChecks(ce)...)
	return ce, nil
}

func parseField(raw string, spec fieldSpec, quartz bool) (fieldSet, []string, error) {
	fs := fieldSet{spec: spec, raw: raw, hash: -1}
	var warns []string
	if raw == "*" || raw == "?" {
		fs.any = true
		fs.values = rangeInts(spec.min, spec.max)
		if raw == "?" && !quartz {
			warns = append(warns, spec.name+": '?' is a Quartz/Spring special; treated as '*'")
		}
		return fs, warns, nil
	}
	// Quartz L / LW / nL / nW / n#k
	if quartz {
		up := strings.ToUpper(raw)
		if up == "L" {
			fs.last = true
			fs.values = []int{spec.max}
			return fs, warns, nil
		}
		if up == "LW" && spec.kind == fkDom {
			fs.last = true
			fs.nearestW = true
			fs.values = []int{spec.max}
			return fs, warns, nil
		}
		if strings.Contains(up, "#") && spec.kind == fkDow {
			parts := strings.SplitN(up, "#", 2)
			d, err1 := parseToken(parts[0], spec)
			k, err2 := strconv.Atoi(parts[1])
			if err1 != nil || err2 != nil || k < 1 || k > 5 {
				return fs, warns, fmt.Errorf("invalid # form %q", raw)
			}
			fs.hash = k
			fs.values = []int{d}
			return fs, warns, nil
		}
		if strings.HasSuffix(up, "W") && spec.kind == fkDom {
			n, err := strconv.Atoi(strings.TrimSuffix(up, "W"))
			if err != nil {
				return fs, warns, fmt.Errorf("invalid W form %q", raw)
			}
			fs.nearestW = true
			fs.values = []int{n}
			return fs, warns, nil
		}
		if strings.HasSuffix(up, "L") && (spec.kind == fkDom || spec.kind == fkDow) {
			n, err := parseToken(strings.TrimSuffix(up, "L"), spec)
			if err != nil {
				return fs, warns, err
			}
			fs.last = true
			fs.values = []int{n}
			return fs, warns, nil
		}
	}
	// comma-separated list of ranges/steps/singles
	seen := map[int]bool{}
	for _, part := range strings.Split(raw, ",") {
		vals, err := parsePart(part, spec)
		if err != nil {
			return fs, warns, err
		}
		for _, v := range vals {
			if !seen[v] {
				seen[v] = true
				fs.values = append(fs.values, v)
			}
		}
	}
	sort.Ints(fs.values)
	return fs, warns, nil
}

func parsePart(part string, spec fieldSpec) ([]int, error) {
	step := 1
	base := part
	if i := strings.IndexByte(part, '/'); i >= 0 {
		base = part[:i]
		s, err := strconv.Atoi(part[i+1:])
		if err != nil || s < 1 {
			return nil, fmt.Errorf("invalid step in %q", part)
		}
		step = s
	}
	var lo, hi int
	if base == "*" {
		lo, hi = spec.min, spec.max
	} else if i := strings.IndexByte(base, '-'); i >= 0 {
		a, err1 := parseToken(base[:i], spec)
		b, err2 := parseToken(base[i+1:], spec)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("invalid range %q", base)
		}
		if a > b {
			return nil, fmt.Errorf("range start > end in %q", base)
		}
		lo, hi = a, b
	} else {
		v, err := parseToken(base, spec)
		if err != nil {
			return nil, err
		}
		if step == 1 {
			return []int{v}, nil
		}
		lo, hi = v, spec.max
	}
	var out []int
	for v := lo; v <= hi; v += step {
		out = append(out, v)
	}
	return out, nil
}

func parseToken(tok string, spec fieldSpec) (int, error) {
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return 0, fmt.Errorf("empty token")
	}
	if spec.names != nil {
		if v, ok := spec.names[strings.ToUpper(tok)]; ok {
			return v, nil
		}
	}
	v, err := strconv.Atoi(tok)
	if err != nil {
		return 0, fmt.Errorf("not a number or name: %q", tok)
	}
	// Dow: 7 == Sunday == 0
	if spec.kind == fkDow && v == 7 {
		v = 0
	}
	if v < spec.min || v > spec.max {
		if !(spec.kind == fkDow && v == 7) {
			return 0, fmt.Errorf("%d out of range [%d,%d]", v, spec.min, spec.max)
		}
	}
	return v, nil
}

func rangeInts(a, b int) []int {
	out := make([]int, 0, b-a+1)
	for i := a; i <= b; i++ {
		out = append(out, i)
	}
	return out
}

// ---------------------------------------------------------------------------
// Matching + next-N runs (timezone-aware)
// ---------------------------------------------------------------------------

func (ce *CronExpr) field(k fieldKind) *fieldSet {
	for i := range ce.Fields {
		if ce.Fields[i].spec.kind == k {
			return &ce.Fields[i]
		}
	}
	return nil
}

func (fs *fieldSet) contains(v int) bool {
	if fs == nil || fs.any {
		return true
	}
	for _, x := range fs.values {
		if x == v {
			return true
		}
	}
	return false
}

// Matches reports whether t satisfies the expression.
func (ce *CronExpr) Matches(t time.Time) bool {
	if ce.Macro == "@reboot" {
		return false
	}
	if ce.HasSec {
		if !ce.field(fkSecond).contains(t.Second()) {
			return false
		}
	} else if t.Second() != 0 {
		// classic cron fires on second 0 of matching minutes
		return false
	}
	if !ce.field(fkMinute).contains(t.Minute()) {
		return false
	}
	if !ce.field(fkHour).contains(t.Hour()) {
		return false
	}
	if !ce.field(fkMonth).contains(int(t.Month())) {
		return false
	}
	dom := ce.field(fkDom)
	dow := ce.field(fkDow)
	domMatch := dom.contains(t.Day())
	dowMatch := dow.contains(int(t.Weekday()))
	// Standard cron: if either DOM or DOW is not '*', the OR rule applies.
	if !dom.any && !dow.any {
		return domMatch || dowMatch
	}
	return domMatch && dowMatch
}

// NextN returns the next n run times after `from` (exclusive), in loc.
func (ce *CronExpr) NextN(from time.Time, n int, loc *time.Location) []time.Time {
	if ce.Macro == "@reboot" || n <= 0 {
		return nil
	}
	t := from.In(loc)
	step := time.Minute
	if ce.HasSec {
		step = time.Second
	} else {
		// align to next whole minute
		t = t.Truncate(time.Minute).Add(time.Minute)
	}
	var out []time.Time
	// Safety bound: search up to 5 years of ticks.
	limit := t.Add(5 * 365 * 24 * time.Hour)
	for t.Before(limit) && len(out) < n {
		if ce.Matches(t) {
			out = append(out, t)
		}
		t = t.Add(step)
	}
	return out
}

// PrevN returns the previous n run times before `from`.
func (ce *CronExpr) PrevN(from time.Time, n int, loc *time.Location) []time.Time {
	if ce.Macro == "@reboot" || n <= 0 {
		return nil
	}
	t := from.In(loc)
	step := time.Minute
	if ce.HasSec {
		step = time.Second
	} else {
		t = t.Truncate(time.Minute)
	}
	t = t.Add(-step)
	var out []time.Time
	limit := t.Add(-5 * 365 * 24 * time.Hour)
	for t.After(limit) && len(out) < n {
		if ce.Matches(t) {
			out = append(out, t)
		}
		t = t.Add(-step)
	}
	return out
}

// ---------------------------------------------------------------------------
// Human explainer
// ---------------------------------------------------------------------------

func (ce *CronExpr) Explain() string {
	if ce.Macro == "@reboot" {
		return "Runs once at system boot/startup."
	}
	var parts []string
	if ce.HasSec {
		parts = append(parts, explainField(*ce.field(fkSecond), "second"))
	}
	parts = append(parts,
		explainField(*ce.field(fkMinute), "minute"),
		explainField(*ce.field(fkHour), "hour"),
	)
	dom := ce.field(fkDom)
	dow := ce.field(fkDow)
	if !dom.any && !dow.any {
		parts = append(parts, "on day-of-month "+listPhrase(dom.values)+" OR on "+dowPhrase(dow.values))
	} else {
		parts = append(parts, explainField(*dom, "day-of-month"))
		parts = append(parts, explainField(*dow, "day-of-week"))
	}
	parts = append(parts, explainField(*ce.field(fkMonth), "month"))
	return "Runs " + strings.Join(parts, ", ") + "."
}

func explainField(fs fieldSet, label string) string {
	if fs.any {
		return "every " + label
	}
	if fs.hash > 0 {
		return fmt.Sprintf("the %s %s of the month", ordinal(fs.hash), dowName(fs.values[0]))
	}
	if fs.last {
		if fs.spec.kind == fkDow {
			return "on the last " + dowName(fs.values[0]) + " of the month"
		}
		return "on the last day of the month"
	}
	if fs.nearestW {
		return fmt.Sprintf("on the weekday nearest to day %d", fs.values[0])
	}
	vals := fs.values
	// detect step pattern
	if step, ok := detectStep(vals, fs.spec.min, fs.spec.max); ok {
		if step == 1 {
			return "every " + label
		}
		return fmt.Sprintf("every %d %ss", step, label)
	}
	if label == "day-of-week" {
		return "on " + dowPhrase(vals)
	}
	if label == "month" {
		return "in " + monthPhrase(vals)
	}
	if label == "hour" {
		return "at " + hourPhrase(vals)
	}
	return "at " + label + " " + listPhrase(vals)
}

func detectStep(vals []int, lo, hi int) (int, bool) {
	if len(vals) < 2 {
		return 0, false
	}
	step := vals[1] - vals[0]
	if step < 1 {
		return 0, false
	}
	expect := []int{}
	for v := vals[0]; v <= hi; v += step {
		expect = append(expect, v)
	}
	if len(expect) != len(vals) {
		return 0, false
	}
	for i := range vals {
		if vals[i] != expect[i] {
			return 0, false
		}
	}
	return step, true
}

func listPhrase(vals []int) string {
	if len(vals) == 0 {
		return "(none)"
	}
	if len(vals) == 1 {
		return strconv.Itoa(vals[0])
	}
	if len(vals) <= 6 {
		ss := make([]string, len(vals))
		for i, v := range vals {
			ss[i] = strconv.Itoa(v)
		}
		return strings.Join(ss, ", ")
	}
	return fmt.Sprintf("%d, %d, … %d (%d values)", vals[0], vals[1], vals[len(vals)-1], len(vals))
}

func dowName(v int) string {
	names := []string{"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"}
	if v >= 0 && v <= 6 {
		return names[v]
	}
	return strconv.Itoa(v)
}
func dowPhrase(vals []int) string {
	ss := make([]string, len(vals))
	for i, v := range vals {
		ss[i] = dowName(v)
	}
	return strings.Join(ss, ", ")
}
func monthName(v int) string {
	names := []string{"", "January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"}
	if v >= 1 && v <= 12 {
		return names[v]
	}
	return strconv.Itoa(v)
}
func monthPhrase(vals []int) string {
	ss := make([]string, len(vals))
	for i, v := range vals {
		ss[i] = monthName(v)
	}
	return strings.Join(ss, ", ")
}
func hourPhrase(vals []int) string {
	ss := make([]string, len(vals))
	for i, v := range vals {
		ss[i] = fmt.Sprintf("%02d:00", v)
	}
	if len(ss) <= 6 {
		return strings.Join(ss, ", ")
	}
	return fmt.Sprintf("%s, %s, … %s (%d hours)", ss[0], ss[1], ss[len(ss)-1], len(ss))
}
func ordinal(n int) string {
	switch n {
	case 1:
		return "1st"
	case 2:
		return "2nd"
	case 3:
		return "3rd"
	default:
		return strconv.Itoa(n) + "th"
	}
}

// ---------------------------------------------------------------------------
// Anomaly / risk checks
// ---------------------------------------------------------------------------

func anomalyChecks(ce *CronExpr) []string {
	var w []string
	if ce.Macro == "@reboot" {
		return w
	}
	min := ce.field(fkMinute)
	hour := ce.field(fkHour)
	dom := ce.field(fkDom)
	dow := ce.field(fkDow)
	// every minute
	if min.any && hour.any {
		w = append(w, "fires every minute of every hour — very high frequency")
	} else if min.any {
		w = append(w, "fires every minute within matching hours")
	}
	// both DOM and DOW constrained (OR semantics surprise)
	if !dom.any && !dow.any {
		w = append(w, "both day-of-month and day-of-week are constrained; cron ORs them (runs if either matches)")
	}
	// impossible DOM/month combos
	month := ce.field(fkMonth)
	if !dom.any && !month.any {
		ok := false
		for _, m := range month.values {
			dim := daysInMonth(m, 2024) // leap year upper bound
			for _, d := range dom.values {
				if d <= dim {
					ok = true
					break
				}
			}
			if ok {
				break
			}
		}
		if !ok {
			w = append(w, "day-of-month never occurs in the selected month(s) — expression never fires")
		}
	}
	// seconds field high frequency
	if ce.HasSec {
		sec := ce.field(fkSecond)
		if sec.any || len(sec.values) > 30 {
			w = append(w, "seconds field is dense — can fire many times per minute")
		}
	}
	// overnight / business-hours hints
	if !hour.any {
		night := 0
		for _, h := range hour.values {
			if h >= 0 && h <= 5 {
				night++
			}
		}
		if night == len(hour.values) && len(hour.values) > 0 {
			w = append(w, "only fires overnight (00:00-05:59)")
		}
	}
	return w
}

func daysInMonth(month, year int) int {
	return time.Date(year, time.Month(month)+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

// FrequencyEstimate returns approximate runs per day.
func (ce *CronExpr) FrequencyEstimate() float64 {
	if ce.Macro == "@reboot" {
		return 0
	}
	minN := float64(len(ce.field(fkMinute).values))
	hourN := float64(len(ce.field(fkHour).values))
	dom := ce.field(fkDom)
	dow := ce.field(fkDow)
	monthN := float64(len(ce.field(fkMonth).values)) / 12.0
	dayFactor := 1.0
	if !dom.any && !dow.any {
		// OR: rough union
		dayFactor = float64(len(dom.values))/30.0 + float64(len(dow.values))/7.0
		if dayFactor > 1 {
			dayFactor = 1
		}
	} else if !dom.any {
		dayFactor = float64(len(dom.values)) / 30.0
	} else if !dow.any {
		dayFactor = float64(len(dow.values)) / 7.0
	}
	perDay := minN * hourN * dayFactor * monthN
	if ce.HasSec {
		perDay *= float64(len(ce.field(fkSecond).values))
	}
	return perDay
}

// ---------------------------------------------------------------------------
// Builder helpers + templates
// ---------------------------------------------------------------------------

func buildCron(min, hour, dom, month, dow string) string {
	return strings.Join([]string{min, hour, dom, month, dow}, " ")
}

type cronTemplate struct {
	name string
	expr string
	desc string
}

var templates = []cronTemplate{
	{"every-minute", "* * * * *", "Every minute"},
	{"every-5-min", "*/5 * * * *", "Every 5 minutes"},
	{"every-15-min", "*/15 * * * *", "Every 15 minutes"},
	{"every-30-min", "*/30 * * * *", "Every 30 minutes"},
	{"hourly", "0 * * * *", "At minute 0 of every hour"},
	{"every-2-hours", "0 */2 * * *", "Every 2 hours"},
	{"daily-midnight", "0 0 * * *", "Daily at 00:00"},
	{"daily-noon", "0 12 * * *", "Daily at 12:00"},
	{"weekdays-9am", "0 9 * * 1-5", "Weekdays at 09:00"},
	{"weekends-10am", "0 10 * * 0,6", "Weekends at 10:00"},
	{"monday-morning", "0 8 * * 1", "Mondays at 08:00"},
	{"friday-afternoon", "30 16 * * 5", "Fridays at 16:30"},
	{"monthly-1st", "0 0 1 * *", "1st of each month at midnight"},
	{"monthly-last-fri", "0 18 * * 5L", "Last Friday of month at 18:00 (Quartz)"},
	{"quarterly", "0 0 1 1,4,7,10 *", "Quarterly on the 1st"},
	{"yearly", "0 0 1 1 *", "Yearly on Jan 1"},
	{"business-hours-hourly", "0 9-17 * * 1-5", "Hourly 09-17 on weekdays"},
	{"nightly-backup", "30 2 * * *", "Nightly backup at 02:30"},
	{"logrotate-ish", "0 0 * * 0", "Weekly Sunday midnight"},
	{"every-10-sec", "*/10 * * * * *", "Every 10 seconds (6-field)"},
}

func printTemplates() {
	rows := [][]string{}
	for _, t := range allTemplates() {
		rows = append(rows, []string{t.name, t.expr, t.desc})
	}
	table([]string{"NAME", "EXPR", "DESCRIPTION"}, rows)
}

func templateByName(name string) (cronTemplate, bool) {
	for _, t := range allTemplates() {
		if t.name == name {
			return t, true
		}
	}
	return cronTemplate{}, false
}

// ---------------------------------------------------------------------------
// Crontab file parser (user crontab format)
// ---------------------------------------------------------------------------

type crontabEntry struct {
	Line    int
	Expr    string
	Command string
	Comment string
	Env     bool
	Parsed  *CronExpr
	Error   string
}

func parseCrontab(data string, quartz bool) []crontabEntry {
	var out []crontabEntry
	for i, ln := range strings.Split(data, "\n") {
		s := strings.TrimSpace(ln)
		if s == "" {
			continue
		}
		if strings.HasPrefix(s, "#") {
			out = append(out, crontabEntry{Line: i + 1, Comment: s})
			continue
		}
		if strings.Contains(s, "=") && !strings.ContainsAny(s[:strings.IndexByte(s, '=')], " \t") {
			out = append(out, crontabEntry{Line: i + 1, Expr: s, Env: true})
			continue
		}
		fields := strings.Fields(s)
		if len(fields) < 6 {
			out = append(out, crontabEntry{Line: i + 1, Expr: s, Error: "too few fields"})
			continue
		}
		// @macros
		expr, cmd := "", ""
		if strings.HasPrefix(fields[0], "@") {
			expr = fields[0]
			cmd = strings.Join(fields[1:], " ")
		} else if quartz && len(fields) >= 7 && isCronToken(fields[0]) && isCronToken(fields[5]) {
			// 6-field (with-seconds) form — only trusted under Quartz/extended parsing,
			// since classic Vixie/system crontabs are always 5-field + command.
			expr = strings.Join(fields[:6], " ")
			cmd = strings.Join(fields[6:], " ")
		} else {
			expr = strings.Join(fields[:5], " ")
			cmd = strings.Join(fields[5:], " ")
		}
		ent := crontabEntry{Line: i + 1, Expr: expr, Command: cmd}
		ce, err := ParseCron(expr, quartz)
		if err != nil {
			ent.Error = err.Error()
		} else {
			ent.Parsed = ce
		}
		out = append(out, ent)
	}
	return out
}

func isIntish(s string) bool {
	if s == "*" || strings.ContainsAny(s, ",-/") {
		return true
	}
	_, err := strconv.Atoi(s)
	return err == nil
}

// isCronToken reports whether s looks like a single cron field token (not a
// command). It rejects paths and words so the 5-vs-6-field heuristic is safe.
func isCronToken(s string) bool {
	if s == "" || s[0] == '/' || s[0] == '.' {
		return false
	}
	hasCore := false
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c == '*', c == '?':
			hasCore = true
		case c == ',' || c == '-' || c == '/' || c == '#':
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		default:
			return false
		}
	}
	return hasCore
}

// ---------------------------------------------------------------------------
// Report builder
// ---------------------------------------------------------------------------

func buildReport(ce *CronExpr, loc *time.Location, nextN int) *Report {
	r := newReport(ce.Raw)
	r.Stats = append(r.Stats, KV{"expression", ce.Raw})
	if ce.Macro != "" {
		r.Stats = append(r.Stats, KV{"macro", ce.Macro})
	}
	r.Stats = append(r.Stats, KV{"fields", strconv.Itoa(len(ce.Fields))})
	r.Stats = append(r.Stats, KV{"has_seconds", boolStr(ce.HasSec)})
	r.Stats = append(r.Stats, KV{"timezone", loc.String()})
	r.Stats = append(r.Stats, KV{"human", ce.Explain()})
	freq := ce.FrequencyEstimate()
	r.Stats = append(r.Stats, KV{"est_runs_per_day", fmt.Sprintf("%.1f", freq)}, KV{"frequency_label", describeFrequency(freq)})
	if isBusinessHoursOnly(ce) {
		r.Stats = append(r.Stats, KV{"business_hours_only", "yes"})
	}
	r.Stats = append(r.Stats, KV{"next_run", nextRunOrNever(ce, loc)})
	if runs1 := ce.NextN(time.Now(), 1, loc); len(runs1) > 0 {
		r.Stats = append(r.Stats, KV{"time_to_next", humanDuration(time.Until(runs1[0]))})
	}
	r.Stats = append(r.Stats, KV{"est_runs_per_week", fmt.Sprintf("%.0f", runsPerWeek(ce))})
	r.Stats = append(r.Stats, KV{"est_runs_per_year", fmt.Sprintf("%.0f", runsPerYear(ce))})
	r.Stats = append(r.Stats, KV{"minute_cardinality", strconv.Itoa(fieldCardinality(ce, fkMinute))})
	r.Stats = append(r.Stats, KV{"warning_count", strconv.Itoa(warningCount(ce))})

	if freq > 1440 {
		r.Findings = append(r.Findings, Finding{ID: "CRON-HIGHFREQ", Title: "Extremely high schedule frequency",
			Severity: "HIGH", Category: "availability", Score: 7.0, ATTCK: []string{"T1053.003"},
			Description: fmt.Sprintf("Estimated ~%.0f runs/day; may overwhelm the target or fill logs.", freq),
			Remediation: "Reduce frequency or add locking (flock) to prevent overlap."})
	} else if freq > 288 {
		r.Findings = append(r.Findings, Finding{ID: "CRON-MEDFREQ", Title: "High schedule frequency",
			Severity: "MEDIUM", Category: "availability", Score: 4.0,
			Description: fmt.Sprintf("Estimated ~%.0f runs/day.", freq)})
	}
	for _, w := range ce.Warnings {
		sev := "LOW"
		if strings.Contains(w, "never fires") {
			sev = "HIGH"
		} else if strings.Contains(w, "every minute") || strings.Contains(w, "high frequency") {
			sev = "MEDIUM"
		}
		r.Findings = append(r.Findings, Finding{ID: "CRON-ANOMALY", Title: "Schedule anomaly",
			Severity: sev, Category: "schedule", Score: float64(sevRank(sev)) * 1.5,
			Description: w, ATTCK: []string{"T1053.003"}})
	}
	if nextN > 0 && ce.Macro != "@reboot" {
		runs := ce.NextN(time.Now(), nextN, loc)
		for i, t := range runs {
			r.Stats = append(r.Stats, KV{fmt.Sprintf("next_%d", i+1), t.Format("2006-01-02 15:04:05 MST")})
		}
		if len(runs) == 0 {
			r.Findings = append(r.Findings, Finding{ID: "CRON-NO-NEXT", Title: "No upcoming runs in search window",
				Severity: "HIGH", Category: "schedule", Score: 7.0,
				Description: "Next-N search found no matching times in 5 years — expression is likely impossible."})
		}
	}
	if nextN > 0 && loc != time.UTC && ce.Macro != "@reboot" {
		for _, w := range dstWarnings(ce, loc) {
			if strings.Contains(w, "SKIPPED") || strings.Contains(w, "TWICE") {
				r.Notes = append(r.Notes, "DST: "+strings.TrimSpace(w))
			}
		}
	}
	if len(r.Findings) == 0 {
		r.Findings = append(r.Findings, Finding{ID: "CRON-OK", Title: "Schedule looks healthy", Severity: "INFO", Category: "schedule", Score: 0, Description: ce.Explain()})
	}
	return r
}

func boolStr(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func crontabReport(entries []crontabEntry, loc *time.Location) *Report {
	r := newReport("crontab")
	jobs, env, comments, errs := 0, 0, 0, 0
	var totalFreq float64
	for _, e := range entries {
		switch {
		case e.Comment != "":
			comments++
		case e.Env:
			env++
		case e.Error != "":
			errs++
			r.Findings = append(r.Findings, Finding{ID: "CRON-PARSE-ERR", Title: "Unparseable crontab line",
				Severity: "MEDIUM", Category: "data-quality", Score: 4.0,
				Description: e.Error, Location: fmt.Sprintf("line %d", e.Line), Evidence: e.Expr})
		case e.Parsed != nil:
			jobs++
			totalFreq += e.Parsed.FrequencyEstimate()
			sub := buildReport(e.Parsed, loc, 0)
			for _, f := range sub.Findings {
				if f.Severity == "INFO" {
					continue
				}
				f.Location = fmt.Sprintf("line %d: %s", e.Line, truncStr(e.Command, 40))
				r.Findings = append(r.Findings, f)
			}
			// command security heuristics (shared audit engine)
			r.Findings = append(r.Findings, auditCommand(e.Command, e.Line)...)
		}
	}
	r.Stats = append(r.Stats,
		KV{"jobs", strconv.Itoa(jobs)},
		KV{"env_vars", strconv.Itoa(env)},
		KV{"comments", strconv.Itoa(comments)},
		KV{"errors", strconv.Itoa(errs)},
		KV{"combined_runs_per_day", fmt.Sprintf("%.1f", totalFreq)},
	)
	return r
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

func usage() {
	banner()
	fmt.Println(col("  USAGE", CY+B) + "  " + APPNAME + " [flags]")
	fmt.Println(col("  No flags → interactive TUI.  Flags → one-shot CLI.", GY))
	fmt.Println()
	printHelpSection("EXPRESSION", []string{
		"--expr EXPR        cron expression (5- or 6-field) or @macro",
		"--quartz           enable Quartz/Spring specials (L, W, #, ?)",
		"--build M H DOM MON DOW   build an expression from field tokens",
	})
	printHelpSection("SCHEDULE", []string{
		"--next N           show next N run times (default 10)",
		"--prev N           show previous N run times",
		"--tz ZONE          IANA timezone (default local)",
		"--from RFC3339     start time for next/prev (default now)",
	})
	printHelpSection("CRONTAB FILE", []string{
		"--crontab FILE     parse+audit a full crontab file",
	})
	printHelpSection("REFERENCE", []string{
		"--templates        list common schedule templates",
		"--template NAME    use a named template as --expr",
		"--macros           list @macro expansions",
		"--heatmap          ASCII calendar of runs this month",
		"--gaps             inter-run duration stats",
		"--systemd          convert to systemd OnCalendar= (simple exprs)",
		"--diff EXPR        field-by-field compare with another expression",
	})
	printHelpSection("ANALYSIS", []string{
		"--at RFC3339       test whether the schedule fires at a time (exit 0/1)",
		"--count-range A,B  count runs between two dates (YYYY-MM-DD or RFC3339)",
		"--lint             style/safety suggestions + normalized form",
		"--normalize        print the canonical (collapsed) expression",
		"--dst              daylight-saving transition risks (pair with --tz)",
	})
	printHelpSection("CONVERT", []string{
		"--convert TARGET   systemd | quartz | k8s | actions | jenkins | aws",
	})
	printHelpSection("REPORTING", []string{
		"--format FMT       txt|md|json|csv|sarif",
		"--output FILE      write report to FILE",
		"--no-color",
	})
	printHelpSection("GENERAL", []string{"--demo  --selftest  --version  -h/--help"})
	printHelpSection("EXAMPLES", []string{
		APPNAME + " --expr '*/5 9-17 * * 1-5' --next 5 --tz America/New_York",
		APPNAME + " --template nightly-backup --format json",
		APPNAME + " --crontab /etc/crontab --format sarif --output cron.sarif",
	})
	line(64)
}

func printVersion() {
	fmt.Printf("%s %s  (OWL suite — khaled.s.haddad / owlsec.org)\n", APPNAME, VERSION)
}

var lastReport *Report
var lastExpr *CronExpr

func main() {
	var (
		expr, tz, from, format, output, crontab, template, buildMin, buildHour, buildDom, buildMon, buildDow string
		nextN, prevN                                                                                         int
		quartz, nocolor, demo, selftest, showVer, showTpl, showMacros                                        bool
	)
	fs := flag.NewFlagSet(APPNAME, flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = usage
	fs.StringVar(&expr, "expr", "", "")
	fs.StringVar(&expr, "e", "", "")
	fs.BoolVar(&quartz, "quartz", false, "")
	fs.IntVar(&nextN, "next", 10, "")
	fs.IntVar(&prevN, "prev", 0, "")
	fs.StringVar(&tz, "tz", "", "")
	fs.StringVar(&from, "from", "", "")
	fs.StringVar(&crontab, "crontab", "", "")
	fs.StringVar(&template, "template", "", "")
	fs.BoolVar(&showTpl, "templates", false, "")
	fs.BoolVar(&showMacros, "macros", false, "")
	fs.StringVar(&buildMin, "build-min", "", "")
	fs.StringVar(&buildHour, "build-hour", "", "")
	fs.StringVar(&buildDom, "build-dom", "", "")
	fs.StringVar(&buildMon, "build-mon", "", "")
	fs.StringVar(&buildDow, "build-dow", "", "")
	fs.StringVar(&format, "format", "txt", "")
	fs.StringVar(&output, "output", "", "")
	fs.BoolVar(&nocolor, "no-color", false, "")
	fs.BoolVar(&demo, "demo", false, "")
	fs.BoolVar(&selftest, "selftest", false, "")
	fs.BoolVar(&showVer, "version", false, "")
	heatmapF := fs.Bool("heatmap", false, "")
	gapsF := fs.Bool("gaps", false, "")
	systemdF := fs.Bool("systemd", false, "")
	diffF := fs.String("diff", "", "")
	corpusF := fs.Bool("corpus", false, "")
	convertF := fs.String("convert", "", "")
	atF := fs.String("at", "", "")
	countRangeF := fs.String("count-range", "", "")
	lintF := fs.Bool("lint", false, "")
	normalizeF := fs.Bool("normalize", false, "")
	dstF := fs.Bool("dst", false, "")
	if err := fs.Parse(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			return
		}
		errMsg(err.Error())
		os.Exit(2)
	}
	if nocolor {
		noColor = true
	}
	loc := time.Local
	if tz != "" {
		l, err := time.LoadLocation(tz)
		if err != nil {
			errMsg("bad timezone: " + err.Error())
			os.Exit(2)
		}
		loc = l
	}
	start := time.Now()
	if from != "" {
		t, err := time.Parse(time.RFC3339, from)
		if err != nil {
			errMsg("--from must be RFC3339")
			os.Exit(2)
		}
		start = t
	}
	switch {
	case showVer:
		printVersion()
		return
	case selftest:
		runSelfTest()
		return
	case demo:
		runDemo(format, output)
		return
	case corpusF != nil && *corpusF:
		p, f, fails := runCorpus(quartz)
		fmt.Printf("corpus: %d passed, %d failed\n", p, f)
		for _, x := range fails {
			fmt.Println(" FAIL", x)
		}
		if f > 0 {
			os.Exit(1)
		}
		return
	case showTpl:
		banner()
		printTemplates()
		return
	case showMacros:
		banner()
		rows := [][]string{}
		for k, v := range macros {
			rows = append(rows, []string{k, v})
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i][0] < rows[j][0] })
		table([]string{"MACRO", "EXPANDS TO"}, rows)
		return
	case crontab != "":
		data, err := os.ReadFile(crontab)
		if err != nil {
			errMsg(err.Error())
			os.Exit(1)
		}
		ents := parseCrontab(string(data), quartz)
		rep := crontabReport(ents, loc)
		_ = emit(rep, format, output)
		return
	}
	if template != "" {
		t, ok := templateByName(template)
		if !ok {
			errMsg("unknown template: " + template)
			os.Exit(2)
		}
		expr = t.expr
	}
	if buildMin != "" {
		expr = buildCron(orStar(buildMin), orStar(buildHour), orStar(buildDom), orStar(buildMon), orStar(buildDow))
	}
	if expr == "" {
		interactive()
		return
	}
	ce, err := ParseCron(expr, quartz)
	if err != nil {
		errMsg(err.Error())
		os.Exit(1)
	}
	lastExpr = ce
	if prevN > 0 {
		for i, t := range ce.PrevN(start, prevN, loc) {
			fmt.Printf("prev_%d = %s\n", i+1, t.Format("2006-01-02 15:04:05 MST"))
		}
	}
	if *heatmapF {
		now := time.Now().In(loc)
		banner()
		fmt.Print(calendarHeatmap(ce, now.Year(), now.Month(), loc))
		return
	}
	if *gapsF {
		banner()
		kvTable(interRunStats(ce, 50, loc))
		return
	}
	if *systemdF {
		cal, note := toSystemdOnCalendar(ce)
		if cal != "" {
			fmt.Println("OnCalendar=" + cal)
		}
		fmt.Println(note)
		return
	}
	if *diffF != "" {
		other, err := ParseCron(*diffF, quartz)
		if err != nil {
			errMsg(err.Error())
			os.Exit(1)
		}
		banner()
		kvTable(diffExprs(ce, other))
		return
	}
	if *convertF != "" {
		banner()
		body, notes := convertTo(ce, *convertF)
		if body != "" {
			fmt.Println(body)
			fmt.Println()
		}
		for _, n := range notes {
			info(n)
		}
		return
	}
	if *atF != "" {
		t, err := parseFlexTime(*atF)
		if err != nil {
			errMsg(err.Error())
			os.Exit(2)
		}
		if ce.Matches(t) {
			okMsg("fires at " + t.Format(time.RFC3339))
			return
		}
		warnMsg("does not fire at " + t.Format(time.RFC3339))
		os.Exit(1)
	}
	if *countRangeF != "" {
		parts := strings.SplitN(*countRangeF, ",", 2)
		if len(parts) != 2 {
			errMsg("--count-range expects A,B (e.g. 2026-01-01,2026-12-31)")
			os.Exit(2)
		}
		ta, e1 := parseFlexTime(parts[0])
		tb, e2 := parseFlexTime(parts[1])
		if e1 != nil || e2 != nil {
			errMsg("--count-range: bad date (use YYYY-MM-DD or RFC3339)")
			os.Exit(2)
		}
		n, capped := countRuns(ce, ta, tb, loc)
		fmt.Println(n)
		if capped {
			warnMsg("search window capped — value is a lower bound")
		}
		return
	}
	if *lintF {
		banner()
		for _, l := range lintExpr(ce) {
			info(l)
		}
		okMsg("normalized: " + normalizeExpr(ce))
		return
	}
	if *normalizeF {
		fmt.Println(normalizeExpr(ce))
		return
	}
	if *dstF {
		banner()
		for _, l := range dstWarnings(ce, loc) {
			info(l)
		}
		return
	}
	rep := buildReport(ce, loc, nextN)
	lastReport = rep
	_ = emit(rep, format, output)
}

func orStar(s string) string {
	if s == "" {
		return "*"
	}
	return s
}

// ---------------------------------------------------------------------------
// Demo + self-test
// ---------------------------------------------------------------------------

func runDemo(format, output string) {
	banner()
	info("demonstrating parse, explain, next-N, and anomaly detection")
	fmt.Println()
	samples := []string{
		"*/5 9-17 * * 1-5",
		"@daily",
		"0 0 31 2 *",
		"* * * * *",
		"30 2 * * *",
		"0 0 * * 5L",
	}
	agg := newReport("demo")
	loc := time.Local
	for _, s := range samples {
		quartz := strings.Contains(s, "L")
		ce, err := ParseCron(s, quartz)
		if err != nil {
			errMsg(s + ": " + err.Error())
			continue
		}
		okMsg(s)
		info("  " + ce.Explain())
		runs := ce.NextN(time.Now(), 3, loc)
		for _, t := range runs {
			info("  next: " + t.Format("2006-01-02 15:04 MST"))
		}
		sub := buildReport(ce, loc, 0)
		for _, f := range sub.Findings {
			if f.Severity != "INFO" {
				agg.Findings = append(agg.Findings, f)
			}
		}
		fmt.Println()
	}
	// synthetic crontab
	ct := `# demo crontab
SHELL=/bin/bash
0 2 * * * /usr/local/bin/backup.sh
*/1 * * * * curl http://example.com/ping
0 0 1 * * chmod 777 /tmp/share
`
	ents := parseCrontab(ct, false)
	cr := crontabReport(ents, loc)
	agg.Findings = append(agg.Findings, cr.Findings...)
	agg.Stats = append(agg.Stats, KV{"sample_expressions", strconv.Itoa(len(samples))})
	agg.Notes = append(agg.Notes, "Demo data is synthetic.")
	showFindingsTUI(agg)
	fmt.Println()
	if output != "" || format != "txt" {
		_ = emit(agg, format, output)
	}
	okMsg("demo complete")
}

func runSelfTest() {
	banner()
	info("running internal self-tests")
	fmt.Println()
	pass, fail := 0, 0
	check := func(n string, c bool) {
		if c {
			pass++
			okMsg(n)
		} else {
			fail++
			errMsg(n)
		}
	}
	ce, err := ParseCron("0 0 * * *", false)
	check("parse @daily-equivalent", err == nil)
	check("explain non-empty", ce != nil && ce.Explain() != "")
	ce2, _ := ParseCron("@hourly", false)
	check("macro expand", ce2 != nil && ce2.Fields[0].raw == "0")
	_, err3 := ParseCron("60 * * * *", false)
	check("reject out-of-range minute", err3 != nil)
	ce4, _ := ParseCron("*/5 * * * *", false)
	check("step parse has 12 values", ce4 != nil && len(ce4.field(fkMinute).values) == 12)
	loc := time.UTC
	from := time.Date(2026, 10, 18, 12, 0, 0, 0, loc)
	runs := ce4.NextN(from, 3, loc)
	check("next-N returns 3", len(runs) == 3)
	check("first next is :05", runs[0].Minute() == 5)
	check("matches works", ce4.Matches(time.Date(2026, 10, 18, 12, 10, 0, 0, loc)))
	check("non-match", !ce4.Matches(time.Date(2026, 10, 18, 12, 7, 0, 0, loc)))
	// OR semantics
	ce5, _ := ParseCron("0 0 1 * 1", false)
	// 2026-10-01 is Thursday; 2026-10-05 is Monday
	check("DOM fires", ce5.Matches(time.Date(2026, 10, 1, 0, 0, 0, 0, loc)))
	check("DOW fires (OR)", ce5.Matches(time.Date(2026, 10, 5, 0, 0, 0, 0, loc)))
	check("neither no-fire", !ce5.Matches(time.Date(2026, 10, 2, 0, 0, 0, 0, loc)))
	// impossible
	ce6, _ := ParseCron("0 0 31 2 *", false)
	check("Feb 31 warns", ce6 != nil && len(ce6.Warnings) > 0)
	// quartz
	ce7, err7 := ParseCron("0 0 * * 5L", true)
	check("quartz 5L parses", err7 == nil && ce7.field(fkDow).last)
	// 6-field
	ce8, err8 := ParseCron("*/10 * * * * *", false)
	check("6-field parses", err8 == nil && ce8.HasSec)
	// crontab
	ents := parseCrontab("0 1 * * * /bin/true\nBAD LINE\n", false)
	check("crontab parses jobs", len(ents) >= 2)
	check("ordinal 1st", ordinal(1) == "1st")
	check("buildCron", buildCron("0", "0", "*", "*", "*") == "0 0 * * *")
	fmt.Println()
	if fail == 0 {
		okMsg(fmt.Sprintf("all %d self-tests passed", pass))
	} else {
		errMsg(fmt.Sprintf("%d passed, %d failed", pass, fail))
		os.Exit(1)
	}
}

// ---------------------------------------------------------------------------
// Interactive TUI
// ---------------------------------------------------------------------------

func interactive() {
	items := []menuItem{
		{"1", "Parse & Explain", "Parse, explain & grade an expression", GRN},
		{"2", "Next Runs", "Upcoming N run times (timezone-aware)", CY},
		{"3", "Previous Runs", "Past N run times", YLW},
		{"4", "Build Expression", "Compose from individual fields", MG},
		{"5", "Templates", "Browse common schedule presets", OR},
		{"6", "Macros", "@daily / @hourly … expansions", BL},
		{"7", "Audit Crontab", "Parse & security-audit a crontab file", R},
		{"8", "Overlap Check", "Find simultaneous firings", W},
		{"9", "Random Expr", "Generate valid random schedules", CY},
		{"10", "Field Reference", "Fields, ranges & operators", MG},
		{"11", "Gap Stats", "Inter-run duration analysis", GRN},
		{"12", "Calendar Heatmap", "Month view of run density", OR},
		{"13", "Convert", "systemd / k8s / Actions / Quartz / AWS", CY},
		{"14", "Diff", "Compare two expressions", YLW},
		{"15", "Holiday Advice", "Holiday-overlap guidance", BL},
		{"16", "Count In Range", "Count runs between two dates", MG},
		{"17", "Fires At?", "Test if it runs at a given time", GRN},
		{"18", "Lint / Normalize", "Suggestions & canonical form", OR},
		{"19", "DST Check", "Daylight-saving transition risks", R},
		{"20", "Validation Corpus", "Run internal test corpus", CY},
		{"21", "Export Report", "Save last report to a file", YLW},
		{"22", "Self-Test", "Run built-in self-tests", GRN},
	}
	for {
		switch showMenu("Cron Builder / Validator / Explainer", items) {
		case "1":
			tuiParse()
		case "2":
			tuiNext()
		case "3":
			tuiPrev()
		case "4":
			tuiBuild()
		case "5":
			clear()
			banner()
			printTemplates()
			pause()
		case "6":
			tuiMacros()
		case "7":
			tuiCrontab()
		case "8":
			tuiOverlap()
		case "9":
			tuiRandom()
		case "10":
			tuiFieldRef()
		case "11":
			tuiGaps()
		case "12":
			tuiHeatmap()
		case "13":
			tuiConvert()
		case "14":
			tuiDiff()
		case "15":
			tuiHoliday()
		case "16":
			tuiCountRange()
		case "17":
			tuiAt()
		case "18":
			tuiLint()
		case "19":
			tuiDST()
		case "20":
			tuiCorpus()
		case "21":
			tuiExport()
		case "22":
			clear()
			banner()
			runSelfTest()
			pause()
		case "h", "H", "help", "?":
			tuiHelp()
		case "0", "00", "q", "Q", "exit", "":
			clear()
			okMsg("goodbye — owlsec.org")
			return
		default:
			warnMsg("unknown selection")
			pause()
		}
	}
}

func tuiParse() {
	clear()
	banner()
	s := prompt("cron expression or @macro")
	q := prompt("quartz specials? y/N") == "y"
	ce, err := ParseCron(s, q)
	if err != nil {
		errMsg(err.Error())
		pause()
		return
	}
	lastExpr = ce
	okMsg(ce.Explain())
	for _, w := range ce.Warnings {
		warnMsg(w)
	}
	lastReport = buildReport(ce, time.Local, 5)
	fmt.Println()
	showFindingsTUI(lastReport)
	pause()
}

func tuiNext() {
	clear()
	banner()
	if lastExpr == nil {
		warnMsg("parse an expression first")
		pause()
		return
	}
	n := atoiSafe(prompt("how many (blank=10)"), 10)
	tz := prompt("timezone (blank=local)")
	loc := time.Local
	if tz != "" {
		if l, err := time.LoadLocation(tz); err == nil {
			loc = l
		} else {
			errMsg(err.Error())
			pause()
			return
		}
	}
	for i, t := range lastExpr.NextN(time.Now(), n, loc) {
		okMsg(fmt.Sprintf("#%d  %s", i+1, t.Format("2006-01-02 15:04:05 MST")))
	}
	pause()
}

func tuiPrev() {
	clear()
	banner()
	if lastExpr == nil {
		warnMsg("parse an expression first")
		pause()
		return
	}
	n := atoiSafe(prompt("how many (blank=5)"), 5)
	for i, t := range lastExpr.PrevN(time.Now(), n, time.Local) {
		okMsg(fmt.Sprintf("#%d  %s", i+1, t.Format("2006-01-02 15:04:05 MST")))
	}
	pause()
}

func tuiBuild() {
	clear()
	banner()
	info("enter field tokens (* , -/ ranges, names OK)")
	min := orStar(prompt("minute"))
	hour := orStar(prompt("hour"))
	dom := orStar(prompt("day-of-month"))
	mon := orStar(prompt("month"))
	dow := orStar(prompt("day-of-week"))
	expr := buildCron(min, hour, dom, mon, dow)
	okMsg("built: " + expr)
	ce, err := ParseCron(expr, false)
	if err != nil {
		errMsg(err.Error())
	} else {
		lastExpr = ce
		info(ce.Explain())
		lastReport = buildReport(ce, time.Local, 5)
	}
	pause()
}

func tuiMacros() {
	clear()
	banner()
	rows := [][]string{}
	for k, v := range macros {
		rows = append(rows, []string{k, v})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i][0] < rows[j][0] })
	table([]string{"MACRO", "EXPANDS TO"}, rows)
	pause()
}

func tuiCrontab() {
	clear()
	banner()
	path := prompt("crontab file path")
	data, err := os.ReadFile(path)
	if err != nil {
		errMsg(err.Error())
		pause()
		return
	}
	ents := parseCrontab(string(data), false)
	lastReport = crontabReport(ents, time.Local)
	for _, kv := range lastReport.Stats {
		info(kv.K + " = " + kv.V)
	}
	fmt.Println()
	showFindingsTUI(lastReport)
	pause()
}

func tuiExport() {
	clear()
	banner()
	if lastReport == nil {
		warnMsg("nothing to export")
		pause()
		return
	}
	f := prompt("format txt/md/json/csv/sarif")
	o := prompt("output file (blank=stdout)")
	if err := emit(lastReport, f, o); err != nil {
		errMsg(err.Error())
	}
	pause()
}

// ---------------------------------------------------------------------------
// Overlap / conflict detection between multiple expressions
// ---------------------------------------------------------------------------

func findOverlaps(exprs []*CronExpr, window time.Duration, loc *time.Location) [][2]int {
	type hit struct {
		t time.Time
		i int
	}
	var hits []hit
	start := time.Now()
	for i, ce := range exprs {
		for _, t := range ce.NextN(start, 200, loc) {
			if t.Sub(start) > window {
				break
			}
			hits = append(hits, hit{t, i})
		}
	}
	sort.Slice(hits, func(a, b int) bool { return hits[a].t.Before(hits[b].t) })
	seen := map[[2]int]bool{}
	var pairs [][2]int
	for i := 0; i < len(hits); i++ {
		for j := i + 1; j < len(hits) && hits[j].t.Equal(hits[i].t); j++ {
			a, b := hits[i].i, hits[j].i
			if a > b {
				a, b = b, a
			}
			key := [2]int{a, b}
			if a != b && !seen[key] {
				seen[key] = true
				pairs = append(pairs, key)
			}
		}
	}
	return pairs
}

func tuiOverlap() {
	clear()
	banner()
	info("enter expressions one per line; empty line to finish")
	var exprs []*CronExpr
	var raws []string
	for {
		s := prompt(fmt.Sprintf("expr #%d", len(exprs)+1))
		if s == "" {
			break
		}
		ce, err := ParseCron(s, false)
		if err != nil {
			errMsg(err.Error())
			continue
		}
		exprs = append(exprs, ce)
		raws = append(raws, s)
	}
	if len(exprs) < 2 {
		warnMsg("need at least 2 expressions")
		pause()
		return
	}
	pairs := findOverlaps(exprs, 7*24*time.Hour, time.Local)
	if len(pairs) == 0 {
		okMsg("no simultaneous firings in the next 7 days")
	} else {
		for _, p := range pairs {
			warnMsg(fmt.Sprintf("overlap: %q  ↔  %q", raws[p[0]], raws[p[1]]))
		}
	}
	pause()
}

// ---------------------------------------------------------------------------
// Random valid expression generator (for fuzzing / training)
// ---------------------------------------------------------------------------

func randomCron(seed int64) string {
	r := newRNG(seed)
	pick := func(opts []string) string { return opts[r.Intn(len(opts))] }
	min := pick([]string{"*", "0", "*/5", "*/15", "*/30", "0,30", "7", "15", "45"})
	hour := pick([]string{"*", "0", "*/2", "9-17", "0-5", "8", "12", "18", "2,14"})
	dom := pick([]string{"*", "1", "15", "1-7", "*/2", "28"})
	mon := pick([]string{"*", "1", "*/3", "1,4,7,10", "6", "12"})
	dow := pick([]string{"*", "1-5", "0", "0,6", "1", "5"})
	// avoid both DOM+DOW constrained sometimes
	if r.Intn(2) == 0 {
		dom = "*"
	} else {
		dow = "*"
	}
	return buildCron(min, hour, dom, mon, dow)
}

// tiny LCG so we stay stdlib-only without math/rand seeding ceremony
type lcg struct{ s uint64 }

func newRNG(seed int64) *lcg {
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	return &lcg{uint64(seed)}
}
func (r *lcg) Intn(n int) int {
	r.s = r.s*6364136223846793005 + 1
	return int((r.s >> 33) % uint64(n))
}

func tuiRandom() {
	clear()
	banner()
	n := atoiSafe(prompt("how many (blank=5)"), 5)
	seed := time.Now().UnixNano()
	rows := [][]string{}
	for i := 0; i < n; i++ {
		expr := randomCron(seed + int64(i)*997)
		ce, err := ParseCron(expr, false)
		desc := ""
		if err == nil {
			desc = truncStr(ce.Explain(), 50)
		} else {
			desc = err.Error()
		}
		rows = append(rows, []string{expr, desc})
	}
	table([]string{"EXPR", "EXPLAIN"}, rows)
	pause()
}

// ---------------------------------------------------------------------------
// Field reference
// ---------------------------------------------------------------------------

func tuiFieldRef() {
	clear()
	banner()
	fmt.Println("  " + col("Cron field reference", CY+B))
	rows := [][]string{
		{"1 (or 0 if 6-field)", "second", "0-59", "6-field only"},
		{"1 (2 if 6f)", "minute", "0-59", ""},
		{"2 (3)", "hour", "0-23", ""},
		{"3 (4)", "day-of-month", "1-31", "L W (Quartz)"},
		{"4 (5)", "month", "1-12 / JAN-DEC", ""},
		{"5 (6)", "day-of-week", "0-7 / SUN-SAT", "0 and 7 = Sunday; L # (Quartz)"},
	}
	table([]string{"POS", "FIELD", "RANGE", "SPECIALS"}, rows)
	fmt.Println()
	info("Operators: * (any)  , (list)  - (range)  / (step)  ? (Quartz any)")
	info("Macros: @yearly @monthly @weekly @daily @hourly @reboot")
	info("DOM+DOW both set → OR semantics (classic Vixie/cron)")
	pause()
}

// ---------------------------------------------------------------------------
// Part 5 — inter-run duration stats, ASCII calendar heatmap, systemd
// OnCalendar conversion, and expression diff.
// ---------------------------------------------------------------------------

func interRunStats(ce *CronExpr, n int, loc *time.Location) []KV {
	runs := ce.NextN(time.Now(), n, loc)
	if len(runs) < 2 {
		return []KV{{"samples", strconv.Itoa(len(runs))}}
	}
	var gaps []time.Duration
	for i := 1; i < len(runs); i++ {
		gaps = append(gaps, runs[i].Sub(runs[i-1]))
	}
	minG, maxG, sum := gaps[0], gaps[0], time.Duration(0)
	for _, g := range gaps {
		if g < minG {
			minG = g
		}
		if g > maxG {
			maxG = g
		}
		sum += g
	}
	avg := sum / time.Duration(len(gaps))
	return []KV{
		{"samples", strconv.Itoa(len(gaps))},
		{"min_gap", minG.String()},
		{"avg_gap", avg.String()},
		{"max_gap", maxG.String()},
	}
}

// calendarHeatmap renders an ASCII month with run-count markers.
func calendarHeatmap(ce *CronExpr, year int, month time.Month, loc *time.Location) string {
	start := time.Date(year, month, 1, 0, 0, 0, 0, loc)
	end := start.AddDate(0, 1, 0)
	counts := map[int]int{}
	t := start
	step := time.Minute
	if ce.HasSec {
		step = time.Second
	}
	for t.Before(end) {
		if ce.Matches(t) {
			counts[t.Day()]++
		}
		t = t.Add(step)
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("  %s %d  (timezone %s)\n", month.String(), year, loc.String()))
	b.WriteString("  Su Mo Tu We Th Fr Sa\n")
	// weekday of the 1st
	pad := int(start.Weekday())
	b.WriteString("  ")
	for i := 0; i < pad; i++ {
		b.WriteString("   ")
	}
	days := daysInMonth(int(month), year)
	for d := 1; d <= days; d++ {
		c := counts[d]
		cell := fmt.Sprintf("%2d", d)
		if c > 0 {
			glyphs := []rune(" ·‥∷▣") // blank · ‥ ∷ ▣
			if c >= 10 {
				cell = "##"
			} else {
				cell = fmt.Sprintf("%s%d", string(glyphs[minI(c, 4)]), d%10)
			}
		}
		b.WriteString(cell + " ")
		if (pad+d)%7 == 0 {
			b.WriteString("\n  ")
		}
	}
	b.WriteString("\n")
	b.WriteString("  legend: blank=0  ·=1 ‥=2 ∷=3 ▣=4+  ##=10+\n")
	return b.String()
}

// toSystemdOnCalendar converts a simple cron to a systemd OnCalendar= string
// when the mapping is unambiguous; otherwise returns an explanation.
func toSystemdOnCalendar(ce *CronExpr) (string, string) {
	if ce.Macro == "@reboot" {
		return "", "Use a systemd oneshot with WantedBy=multi-user.target instead of @reboot."
	}
	if ce.HasSec {
		return "", "systemd OnCalendar has second precision via forms like *-*-* *:*:00; conversion skipped for dense second fields."
	}
	min := ce.field(fkMinute)
	hour := ce.field(fkHour)
	dom := ce.field(fkDom)
	mon := ce.field(fkMonth)
	dow := ce.field(fkDow)
	// only handle simple single-value / * cases cleanly
	single := func(fs *fieldSet) (string, bool) {
		if fs.any {
			return "*", true
		}
		if len(fs.values) == 1 {
			return strconv.Itoa(fs.values[0]), true
		}
		return "", false
	}
	mi, ok1 := single(min)
	ho, ok2 := single(hour)
	d, ok3 := single(dom)
	mo, ok4 := single(mon)
	if !(ok1 && ok2 && ok3 && ok4) {
		return "", "Expression uses lists/ranges/steps — write OnCalendar manually or split into multiple unit drop-ins."
	}
	dowPart := ""
	if !dow.any {
		if len(dow.values) == 1 {
			dowPart = dowName(dow.values[0])[:3] + " "
		} else {
			return "", "Multiple DOW values — use multiple OnCalendar= lines."
		}
	}
	// systemd: Dow YYYY-MM-DD HH:MM:SS
	cal := fmt.Sprintf("%s*-%s-%s %s:%s:00", dowPart, pad2(mo), pad2(d), pad2(ho), pad2(mi))
	return cal, "Map to a systemd timer with OnCalendar=" + cal
}

func pad2(s string) string {
	if s == "*" {
		return "*"
	}
	if len(s) == 1 {
		return "0" + s
	}
	return s
}

// diffExprs compares two expressions field-by-field.
func diffExprs(a, b *CronExpr) []KV {
	var out []KV
	out = append(out, KV{"a", a.Raw}, KV{"b", b.Raw})
	out = append(out, KV{"a_explain", a.Explain()}, KV{"b_explain", b.Explain()})
	kinds := []fieldKind{fkMinute, fkHour, fkDom, fkMonth, fkDow}
	if a.HasSec || b.HasSec {
		kinds = append([]fieldKind{fkSecond}, kinds...)
	}
	for _, k := range kinds {
		fa, fb := a.field(k), b.field(k)
		ar, br := "*", "*"
		if fa != nil {
			ar = fa.raw
		}
		if fb != nil {
			br = fb.raw
		}
		name := "field"
		if fa != nil {
			name = fa.spec.name
		} else if fb != nil {
			name = fb.spec.name
		}
		mark := "="
		if ar != br {
			mark = "≠"
		}
		out = append(out, KV{name, fmt.Sprintf("%s  %s  %s", ar, mark, br)})
	}
	return out
}

func tuiGaps() {
	clear()
	banner()
	if lastExpr == nil {
		warnMsg("parse an expression first")
		pause()
		return
	}
	kvTable(interRunStats(lastExpr, 50, time.Local))
	pause()
}

func tuiHeatmap() {
	clear()
	banner()
	if lastExpr == nil {
		warnMsg("parse an expression first")
		pause()
		return
	}
	now := time.Now()
	fmt.Print(calendarHeatmap(lastExpr, now.Year(), now.Month(), time.Local))
	pause()
}

func tuiSystemd() {
	clear()
	banner()
	if lastExpr == nil {
		warnMsg("parse an expression first")
		pause()
		return
	}
	cal, note := toSystemdOnCalendar(lastExpr)
	if cal != "" {
		okMsg("OnCalendar=" + cal)
	}
	info(note)
	pause()
}

func tuiDiff() {
	clear()
	banner()
	a, e1 := ParseCron(prompt("expression A"), false)
	b, e2 := ParseCron(prompt("expression B"), false)
	if e1 != nil || e2 != nil {
		errMsg("parse error")
		pause()
		return
	}
	kvTable(diffExprs(a, b))
	pause()
}

// ---------------------------------------------------------------------------
// Part 6 — extended template library, holiday-skip advice, validation corpus.
// ---------------------------------------------------------------------------

var moreTemplates = []cronTemplate{
	{"every-10-min", "*/10 * * * *", "Every 10 minutes"},
	{"every-20-min", "*/20 * * * *", "Every 20 minutes"},
	{"bi-hourly", "0 */2 * * *", "Every other hour"},
	{"six-hourly", "0 */6 * * *", "Every 6 hours"},
	{"twice-daily", "0 0,12 * * *", "Midnight and noon"},
	{"weekday-lunch", "0 12 * * 1-5", "Weekday noon"},
	{"weekday-eod", "0 18 * * 1-5", "Weekday 18:00"},
	{"sat-morning", "0 9 * * 6", "Saturday 09:00"},
	{"sun-evening", "0 20 * * 0", "Sunday 20:00"},
	{"1st-and-15th", "0 6 1,15 * *", "1st and 15th at 06:00"},
	{"workday-open", "0 8 * * 1-5", "Weekday open 08:00"},
	{"workday-close", "30 17 * * 1-5", "Weekday close 17:30"},
	{"jan-1", "0 0 1 1 *", "New Year midnight"},
	{"tax-day-ish", "0 9 15 4 *", "Apr 15 09:00"},
	{"monthly-report", "0 7 1 * *", "Monthly report 07:00 on the 1st"},
	{"weekly-digest", "0 8 * * 1", "Monday digest 08:00"},
	{"offpeak-heavy", "0 3 * * *", "Off-peak heavy job 03:00"},
	{"top-of-hour", "0 * * * *", "Top of every hour"},
	{"bottom-of-hour", "30 * * * *", "Bottom of every hour"},
	{"quarter-hours", "0,15,30,45 * * * *", "Every quarter hour"},
}

func allTemplates() []cronTemplate {
	return append(append([]cronTemplate{}, templates...), moreTemplates...)
}

func holidaySkipAdvice(ce *CronExpr) []string {
	var out []string
	dow := ce.field(fkDow)
	dom := ce.field(fkDom)
	if dow.any && dom.any {
		out = append(out, "Runs every day including holidays — consider wrapping the command with a holiday calendar check.")
	}
	if !dow.any {
		weekendOnly := true
		for _, d := range dow.values {
			if d != 0 && d != 6 {
				weekendOnly = false
				break
			}
		}
		if weekendOnly {
			out = append(out, "Weekend-only schedule — holiday overlap is usually fine.")
		}
	}
	if len(out) == 0 {
		out = append(out, "No specific holiday guidance; verify manually against your org calendar.")
	}
	return out
}

type corpusCase struct {
	expr  string
	valid bool
	note  string
}

var validationCorpus = []corpusCase{
	{"* * * * *", true, "every minute"},
	{"0 0 * * *", true, "daily midnight"},
	{"*/5 * * * *", true, "step 5"},
	{"0 9-17 * * 1-5", true, "business hours"},
	{"@hourly", true, "macro"},
	{"@reboot", true, "reboot macro"},
	{"0 0 31 2 *", true, "valid syntax, impossible date"},
	{"60 * * * *", false, "minute out of range"},
	{"0 24 * * *", false, "hour out of range"},
	{"0 0 32 * *", false, "DOM out of range"},
	{"0 0 * 13 *", false, "month out of range"},
	{"0 0 * * 8", false, "DOW out of range"},
	{"0 0 * * SUN", true, "named DOW"},
	{"0 0 1 JAN *", true, "named month"},
	{"0 0 * * 7", true, "DOW 7 = Sunday"},
	{"* * *", false, "too few fields"},
	{"* * * * * * *", false, "too many fields"},
	{"0 0 1W * *", false, "W requires --quartz"},
	{"*/10 * * * * *", true, "6-field every 10s"},
	{"0 0 L * *", false, "L requires --quartz"},
}

func runCorpus(quartz bool) (pass, fail int, failures []string) {
	for _, c := range validationCorpus {
		_, err := ParseCron(c.expr, quartz)
		ok := err == nil
		if ok == c.valid {
			pass++
		} else {
			fail++
			failures = append(failures, fmt.Sprintf("%q want valid=%v got err=%v (%s)", c.expr, c.valid, err, c.note))
		}
	}
	return
}

func tuiCorpus() {
	clear()
	banner()
	p, f, fails := runCorpus(false)
	okMsg(fmt.Sprintf("corpus: %d passed, %d failed", p, f))
	for _, x := range fails {
		errMsg(x)
	}
	pause()
}

func tuiHoliday() {
	clear()
	banner()
	if lastExpr == nil {
		warnMsg("parse an expression first")
		pause()
		return
	}
	for _, a := range holidaySkipAdvice(lastExpr) {
		info(a)
	}
	pause()
}

// describeFrequency returns a human label for a runs-per-day estimate.
func describeFrequency(perDay float64) string {
	switch {
	case perDay <= 0:
		return "never / on-boot only"
	case perDay < 1:
		return "less than daily"
	case perDay < 2:
		return "about once daily"
	case perDay < 24:
		return "several times per day"
	case perDay < 288:
		return "many times per hour"
	case perDay < 1440:
		return "near-continuous (every few minutes)"
	default:
		return "extreme (multiple times per minute)"
	}
}

// nextRunOrNever returns the next run formatted, or a sentinel.
func nextRunOrNever(ce *CronExpr, loc *time.Location) string {
	runs := ce.NextN(time.Now(), 1, loc)
	if len(runs) == 0 {
		return "(none in search window)"
	}
	return runs[0].Format("2006-01-02 15:04:05 MST")
}

// isBusinessHoursOnly reports whether every hour value is in 09-17.
func isBusinessHoursOnly(ce *CronExpr) bool {
	h := ce.field(fkHour)
	if h == nil || h.any {
		return false
	}
	for _, v := range h.values {
		if v < 9 || v > 17 {
			return false
		}
	}
	return true
}

// runsPerWeek estimates weekly firings from the per-day figure.
func runsPerWeek(ce *CronExpr) float64 { return ce.FrequencyEstimate() * 7 }

// runsPerYear estimates yearly firings.
func runsPerYear(ce *CronExpr) float64 { return ce.FrequencyEstimate() * 365.25 }

// fieldCardinality returns how many discrete values a field expands to.
func fieldCardinality(ce *CronExpr, k fieldKind) int {
	f := ce.field(k)
	if f == nil {
		return 0
	}
	return len(f.values)
}

func warningCount(ce *CronExpr) int { return len(ce.Warnings) }

// ============================================================================
//  Part 7 — OWL enhancements: scheduler converters, range counting, point-in-
//  time checks, lint/normalise, DST-transition analysis, and command auditing.
// ============================================================================

// rawField returns the original token for a field kind, or def if absent.
func rawField(ce *CronExpr, k fieldKind, def string) string {
	if f := ce.field(k); f != nil && f.raw != "" {
		return f.raw
	}
	return def
}

// standard5 returns the classic 5-field expression (expanding @macros).
func standard5(ce *CronExpr) string {
	if ce.Macro != "" {
		if v, ok := macros[ce.Macro]; ok && v != "@reboot" {
			return v
		}
	}
	return strings.Join([]string{
		rawField(ce, fkMinute, "*"), rawField(ce, fkHour, "*"),
		rawField(ce, fkDom, "*"), rawField(ce, fkMonth, "*"), rawField(ce, fkDow, "*"),
	}, " ")
}

// humanDuration renders a duration as "1d 2h 3m 4s" (largest non-zero units).
func humanDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	d = d.Round(time.Second)
	days := int(d / (24 * time.Hour))
	d -= time.Duration(days) * 24 * time.Hour
	h := int(d / time.Hour)
	d -= time.Duration(h) * time.Hour
	m := int(d / time.Minute)
	d -= time.Duration(m) * time.Minute
	s := int(d / time.Second)
	var p []string
	if days > 0 {
		p = append(p, strconv.Itoa(days)+"d")
	}
	if h > 0 {
		p = append(p, strconv.Itoa(h)+"h")
	}
	if m > 0 {
		p = append(p, strconv.Itoa(m)+"m")
	}
	if s > 0 || len(p) == 0 {
		p = append(p, strconv.Itoa(s)+"s")
	}
	return strings.Join(p, " ")
}

// parseFlexTime accepts RFC3339 or common date/time layouts in local time.
func parseFlexTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	layouts := []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02 15:04", "2006-01-02"}
	for _, l := range layouts {
		if t, err := time.ParseInLocation(l, s, time.Local); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized time %q (use YYYY-MM-DD[ HH:MM] or RFC3339)", s)
}

// countRuns counts firings in [from,to]; capped guards against runaway scans.
func countRuns(ce *CronExpr, from, to time.Time, loc *time.Location) (int, bool) {
	if ce.Macro == "@reboot" {
		return 0, false
	}
	if to.Before(from) {
		from, to = to, from
	}
	step := time.Minute
	if ce.HasSec {
		step = time.Second
	}
	t := from.In(loc)
	if !ce.HasSec {
		t = t.Truncate(time.Minute)
	}
	const maxIter = 6000000
	cnt, it := 0, 0
	for !t.After(to) {
		if it > maxIter {
			return cnt, true
		}
		if ce.Matches(t) {
			cnt++
		}
		t = t.Add(step)
		it++
	}
	return cnt, false
}

// ---- linting + normalisation --------------------------------------------

func lintExpr(ce *CronExpr) []string {
	if ce.Macro == "@reboot" {
		return []string{"@reboot runs once at boot; nothing to lint."}
	}
	var out []string
	for i := range ce.Fields {
		f := &ce.Fields[i]
		if f.any || f.last || f.hash > 0 || f.nearestW {
			continue
		}
		full := f.spec.max - f.spec.min + 1
		if len(f.values) == full && f.raw != "*" {
			out = append(out, fmt.Sprintf("%s: '%s' covers the whole range — use '*'.", f.spec.name, f.raw))
		}
		if step, ok := detectStep(f.values, f.spec.min, f.spec.max); ok && step > 1 && strings.Contains(f.raw, ",") {
			out = append(out, fmt.Sprintf("%s: '%s' is an even step — use '*/%d'.", f.spec.name, f.raw, step))
		}
	}
	dom, dow := ce.field(fkDom), ce.field(fkDow)
	if dom != nil && dow != nil && !dom.any && !dow.any {
		out = append(out, "day-of-month and day-of-week are both set — classic cron runs when EITHER matches (OR). Set one to '*' if you meant AND.")
	}
	if norm := normalizeExpr(ce); ce.Macro == "" && norm != strings.TrimSpace(ce.Raw) {
		out = append(out, "canonical form: "+norm)
	}
	if len(out) == 0 {
		out = append(out, "No suggestions — expression is already clean.")
	}
	return out
}

// collapseRanges turns a sorted value list into "1-3,7,9-11" form.
func collapseRanges(vals []int) string {
	if len(vals) == 0 {
		return "*"
	}
	var segs []string
	for i := 0; i < len(vals); {
		j := i
		for j+1 < len(vals) && vals[j+1] == vals[j]+1 {
			j++
		}
		switch {
		case j == i:
			segs = append(segs, strconv.Itoa(vals[i]))
		case j == i+1:
			segs = append(segs, strconv.Itoa(vals[i]), strconv.Itoa(vals[j]))
		default:
			segs = append(segs, fmt.Sprintf("%d-%d", vals[i], vals[j]))
		}
		i = j + 1
	}
	return strings.Join(segs, ",")
}

func normalizeField(f *fieldSet) string {
	if f.any {
		return "*"
	}
	if f.last || f.hash > 0 || f.nearestW || len(f.values) == 0 {
		return f.raw
	}
	if len(f.values) == f.spec.max-f.spec.min+1 {
		return "*"
	}
	if step, ok := detectStep(f.values, f.spec.min, f.spec.max); ok && step > 1 {
		if f.values[0] == f.spec.min && f.values[len(f.values)-1]+step > f.spec.max {
			return fmt.Sprintf("*/%d", step)
		}
		return fmt.Sprintf("%d-%d/%d", f.values[0], f.values[len(f.values)-1], step)
	}
	return collapseRanges(f.values)
}

func normalizeExpr(ce *CronExpr) string {
	if ce.Macro == "@reboot" {
		return "@reboot"
	}
	if ce.Macro != "" {
		if v, ok := macros[ce.Macro]; ok {
			if ce2, err := ParseCron(v, false); err == nil {
				return normalizeExpr(ce2)
			}
		}
	}
	var parts []string
	for i := range ce.Fields {
		parts = append(parts, normalizeField(&ce.Fields[i]))
	}
	return strings.Join(parts, " ")
}

// ---- DST analysis -------------------------------------------------------

func dstWarnings(ce *CronExpr, loc *time.Location) []string {
	if ce.Macro == "@reboot" {
		return []string{"@reboot is unaffected by daylight-saving changes."}
	}
	var out []string
	start := time.Now().In(loc)
	end := start.AddDate(1, 0, 0)
	_, prevOff := start.Zone()
	hourF := ce.field(fkHour)
	for t := start; t.Before(end); t = t.Add(time.Hour) {
		_, off := t.Zone()
		if off == prevOff {
			continue
		}
		delta := (off - prevOff) / 3600
		if delta > 0 {
			out = append(out, t.Format("2006-01-02 15:04 MST")+": spring-forward — a wall-clock hour is skipped")
		} else {
			out = append(out, t.Format("2006-01-02 15:04 MST")+": fall-back — a wall-clock hour repeats")
		}
		switch {
		case hourF == nil || hourF.any:
			if delta > 0 {
				out = append(out, "  → every-hour schedule: one run is SKIPPED on this date.")
			} else {
				out = append(out, "  → every-hour schedule: one run fires TWICE on this date.")
			}
		default:
			wh := t.Hour()
			for _, h := range hourF.values {
				if absI(h-wh) <= 1 {
					if delta > 0 {
						out = append(out, fmt.Sprintf("  → runs near %02d:00 may be SKIPPED on this date.", h))
					} else {
						out = append(out, fmt.Sprintf("  → runs near %02d:00 may fire TWICE on this date.", h))
					}
				}
			}
		}
		prevOff = off
	}
	if len(out) == 0 {
		out = append(out, "No DST transitions affect "+loc.String()+" over the next year.")
	}
	return out
}

// ---- scheduler converters ----------------------------------------------

func convertTo(ce *CronExpr, target string) (string, []string) {
	switch strings.ToLower(strings.TrimSpace(target)) {
	case "systemd", "timer":
		cal, note := toSystemdOnCalendar(ce)
		if cal != "" {
			return "OnCalendar=" + cal, []string{note}
		}
		return "", []string{note}
	case "quartz":
		return toQuartz(ce)
	case "k8s", "kubernetes", "cronjob":
		return toK8sCronJob(ce)
	case "actions", "github", "gha":
		return toGitHubActions(ce)
	case "jenkins":
		return toJenkins(ce)
	case "aws", "eventbridge", "event-bridge":
		return toAWSEventBridge(ce)
	default:
		return "", []string{"unknown target '" + target + "' (systemd | quartz | k8s | actions | jenkins | aws)"}
	}
}

func quartzDow(s string, notes *[]string) string {
	if strings.ContainsAny(s, "/-,") {
		*notes = append(*notes, "day-of-week '"+s+"' kept verbatim — verify Quartz numbering (1=SUN..7=SAT).")
		return s
	}
	if v, err := strconv.Atoi(s); err == nil {
		return strconv.Itoa((v % 7) + 1) // cron 0-6 (SUN=0) → Quartz 1-7 (SUN=1)
	}
	return strings.ToUpper(s)
}

// quartzDayFields resolves the Quartz/AWS "exactly one of DOM/DOW is ?" rule.
func quartzDayFields(dom, dow string, notes *[]string) (string, string) {
	switch {
	case dom == "*" && dow == "*":
		return "*", "?"
	case dom != "*" && dow == "*":
		return dom, "?"
	case dom == "*" && dow != "*":
		return "?", quartzDow(dow, notes)
	default:
		*notes = append(*notes, "cannot OR day-of-month and day-of-week — set day-of-week to '?' and kept day-of-month.")
		return dom, "?"
	}
}

func toQuartz(ce *CronExpr) (string, []string) {
	if ce.Macro == "@reboot" {
		return "", []string{"Quartz has no @reboot; use an application startup trigger."}
	}
	var notes []string
	sec := "0"
	if ce.HasSec {
		sec = rawField(ce, fkSecond, "0")
	}
	dom, dow := quartzDayFields(rawField(ce, fkDom, "*"), rawField(ce, fkDow, "*"), &notes)
	expr := strings.Join([]string{sec, rawField(ce, fkMinute, "*"), rawField(ce, fkHour, "*"),
		dom, rawField(ce, fkMonth, "*"), dow}, " ")
	notes = append(notes, "Quartz order: sec min hour day-of-month month day-of-week [year]; DOW is 1=SUN..7=SAT.")
	return expr, notes
}

func toK8sCronJob(ce *CronExpr) (string, []string) {
	if ce.Macro == "@reboot" {
		return "", []string{"Kubernetes has no @reboot; use an init container or a Job on startup."}
	}
	var notes []string
	if ce.HasSec {
		notes = append(notes, "Kubernetes CronJob has no seconds field — seconds dropped.")
	}
	sched := standard5(ce)
	y := "apiVersion: batch/v1\n" +
		"kind: CronJob\n" +
		"metadata:\n" +
		"  name: ocg-job\n" +
		"spec:\n" +
		"  schedule: \"" + sched + "\"\n" +
		"  # timeZone: \"UTC\"   # k8s >=1.27 for IANA zones\n" +
		"  concurrencyPolicy: Forbid\n" +
		"  jobTemplate:\n" +
		"    spec:\n" +
		"      template:\n" +
		"        spec:\n" +
		"          restartPolicy: OnFailure\n" +
		"          containers:\n" +
		"            - name: job\n" +
		"              image: busybox:1.36\n" +
		"              command: [\"/bin/sh\", \"-c\", \"echo run\"]"
	notes = append(notes, "Schedules run in the controller timezone (often UTC) unless .spec.timeZone is set.")
	return y, notes
}

func toGitHubActions(ce *CronExpr) (string, []string) {
	if ce.Macro == "@reboot" {
		return "", []string{"GitHub Actions has no @reboot; use push or workflow_dispatch triggers."}
	}
	var notes []string
	if ce.HasSec {
		notes = append(notes, "GitHub Actions cron is 5-field (no seconds) — seconds dropped.")
	}
	sched := standard5(ce)
	y := "on:\n  schedule:\n    - cron: '" + sched + "'"
	notes = append(notes, "Actions cron runs in UTC, may be delayed under load, and should not be shorter than ~5 minutes.")
	return y, notes
}

func toJenkins(ce *CronExpr) (string, []string) {
	if ce.Macro == "@reboot" {
		return "", []string{"Jenkins has no @reboot; use a build trigger or startup hook."}
	}
	var notes []string
	sched := standard5(ce)
	if f := strings.Fields(sched); len(f) == 5 && f[0] != "*" && !strings.ContainsAny(f[0], "*/,-") {
		h := append([]string{"H"}, f[1:]...)
		notes = append(notes, "load-spread form (recommended): "+strings.Join(h, " "))
	}
	notes = append(notes, "Jenkins supports H (hash) to spread load across the window; prefer it over a fixed minute.")
	return sched, notes
}

func toAWSEventBridge(ce *CronExpr) (string, []string) {
	if ce.Macro == "@reboot" {
		return "", []string{"EventBridge has no @reboot; trigger on an instance/boot event instead."}
	}
	var notes []string
	if ce.HasSec {
		notes = append(notes, "EventBridge cron has no seconds field — seconds dropped.")
	}
	dom, dow := quartzDayFields(rawField(ce, fkDom, "*"), rawField(ce, fkDow, "*"), &notes)
	expr := "cron(" + strings.Join([]string{rawField(ce, fkMinute, "*"), rawField(ce, fkHour, "*"),
		dom, rawField(ce, fkMonth, "*"), dow, "*"}, " ") + ")"
	notes = append(notes, "AWS: cron(Minutes Hours Day-of-month Month Day-of-week Year), UTC, DOW 1=SUN..7=SAT.")
	return expr, notes
}

// ---- command security audit (used by crontab auditing) ------------------

func containsAny(s string, subs ...string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

func firstToken(cmd string) string {
	f := strings.Fields(strings.TrimSpace(cmd))
	if len(f) == 0 {
		return ""
	}
	// skip a leading inline env assignment (FOO=bar cmd)
	if strings.Contains(f[0], "=") && !strings.HasPrefix(f[0], "/") {
		if len(f) > 1 {
			return f[1]
		}
		return ""
	}
	return f[0]
}

func isShellBuiltinish(s string) bool {
	switch s {
	case "cd", "echo", "test", "[", "export", "source", ".", "set", "unset",
		"umask", "wait", "true", "false", "sleep", "exec", "eval", "read":
		return true
	}
	return false
}

// auditCommand runs defensive heuristics over a scheduled command line.
func auditCommand(cmd string, lineNo int) []Finding {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return nil
	}
	var fs []Finding
	loc := fmt.Sprintf("line %d", lineNo)
	ev := truncStr(cmd, 90)
	low := strings.ToLower(cmd)
	add := func(id, title, sev, cat string, score float64, attck []string, cwe, desc string) {
		fs = append(fs, Finding{ID: id, Title: title, Severity: sev, Category: cat, Score: score,
			ATTCK: attck, CWE: cwe, Description: desc, Location: loc, Evidence: ev})
	}
	pipeShell := containsAny(low, "| sh", "|sh", "| bash", "|bash", "|/bin/sh", "| /bin/sh")

	if containsAny(low, "curl ", "wget ") && strings.Contains(low, "http://") {
		add("CRON-CLEARTEXT-FETCH", "Scheduled download over cleartext HTTP", "MEDIUM", "supply-chain",
			5.0, []string{"T1105"}, "CWE-319",
			"Job fetches content via http:// — susceptible to MITM content/code tampering.")
	}
	if pipeShell && containsAny(low, "curl", "wget", "fetch ") {
		add("CRON-CURL-PIPE-SH", "Remote script piped straight into a shell", "HIGH", "supply-chain",
			8.0, []string{"T1059.004", "T1105"}, "CWE-494",
			"The curl|sh pattern executes downloaded content unverified — full RCE if the source or transport is compromised.")
	} else if pipeShell {
		add("CRON-PIPE-SH", "Output piped into a shell interpreter", "MEDIUM", "execution",
			5.0, []string{"T1059.004"}, "",
			"Piping data into sh/bash can execute attacker-influenced content.")
	}
	if containsAny(low, "base64 -d", "base64 --decode", "| base64") && (pipeShell || strings.Contains(low, "eval")) {
		add("CRON-OBFUSCATED-EXEC", "Base64-decoded content executed", "HIGH", "execution",
			7.5, []string{"T1027", "T1059.004"}, "",
			"Base64 decoding feeding a shell/eval is a common obfuscation for malicious payloads.")
	}
	if containsAny(low, "/dev/tcp/", "nc -e", "ncat -e", "exec 5<>") {
		add("CRON-REVERSE-SHELL", "Possible reverse-shell pattern", "CRITICAL", "execution",
			9.5, []string{"T1059.004", "T1071"}, "",
			"Command resembles a reverse shell (/dev/tcp, nc -e, fd redirection).")
	}
	if containsAny(low, "chmod 777", "chmod -r 777", "chmod 0777") {
		add("CRON-CHMOD777", "World-writable permissions set on a schedule", "HIGH", "permissions",
			7.0, []string{"T1222.002"}, "CWE-732",
			"chmod 777 grants world write/execute; resetting it on a schedule defeats hardening.")
	}
	if strings.Contains(low, "rm -rf /") && !containsAny(low, "rm -rf ./", "rm -rf /tmp", "rm -rf \"$") {
		add("CRON-DESTRUCTIVE-RM", "Destructive recursive delete", "HIGH", "integrity",
			7.5, []string{"T1485"}, "",
			"Scheduled 'rm -rf /…' can irreversibly destroy data if a path variable is empty/unset.")
	}
	if strings.Contains(cmd, "AKIA") || strings.Contains(cmd, "-----BEGIN") ||
		containsAny(low, "password=", "passwd=", "token=", "secret=", "apikey=", "api_key=", "aws_secret") {
		add("CRON-HARDCODED-SECRET", "Hard-coded credential/secret in command", "HIGH", "secrets",
			7.0, []string{"T1552.001"}, "CWE-798",
			"Secrets embedded in a crontab leak via ps, logs, and world-readable process state.")
	}
	if !strings.ContainsAny(cmd, ">") && !strings.Contains(cmd, "2>") && !strings.Contains(low, "mailto") {
		add("CRON-NO-REDIRECT", "No output redirection", "INFO", "hygiene",
			0.5, nil, "",
			"Job output is emailed to the owner by default; redirect to a log (>> file 2>&1) to avoid mail spam and capture errors.")
	}
	if ft := firstToken(cmd); ft != "" && !strings.HasPrefix(ft, "/") &&
		!strings.HasPrefix(ft, "@") && !isShellBuiltinish(ft) {
		add("CRON-RELATIVE-PATH", "Command uses a relative / PATH-resolved binary", "LOW", "integrity",
			2.0, []string{"T1574"}, "CWE-426",
			"cron runs with a minimal PATH; a relative command name is ambiguous and PATH-hijackable — use an absolute path.")
	}
	return fs
}

// ---- new interactive screens -------------------------------------------

func tuiConvert() {
	clear()
	banner()
	header("Convert Schedule")
	if lastExpr == nil {
		warnMsg("parse an expression first (menu option 1)")
		pause()
		return
	}
	t := prompt("target (systemd/quartz/k8s/actions/jenkins/aws)")
	body, notes := convertTo(lastExpr, t)
	if body != "" {
		fmt.Println()
		fmt.Println(col(body, W))
	}
	fmt.Println()
	for _, n := range notes {
		info(n)
	}
	pause()
}

func tuiCountRange() {
	clear()
	banner()
	header("Count Runs In Range")
	if lastExpr == nil {
		warnMsg("parse an expression first (menu option 1)")
		pause()
		return
	}
	ta, e1 := parseFlexTime(prompt("from (YYYY-MM-DD or RFC3339)"))
	tb, e2 := parseFlexTime(prompt("to   (YYYY-MM-DD or RFC3339)"))
	if e1 != nil || e2 != nil {
		errMsg("bad date — use 2026-01-31 or a full RFC3339 timestamp")
		pause()
		return
	}
	n, capped := countRuns(lastExpr, ta, tb, time.Local)
	okMsg(fmt.Sprintf("%s run(s) between %s and %s", commaInt(int64(n)),
		ta.Format("2006-01-02"), tb.Format("2006-01-02")))
	if capped {
		warnMsg("search window was capped — result is a lower bound")
	}
	pause()
}

func tuiAt() {
	clear()
	banner()
	header("Point-in-time Check")
	if lastExpr == nil {
		warnMsg("parse an expression first (menu option 1)")
		pause()
		return
	}
	t, err := parseFlexTime(prompt("datetime (YYYY-MM-DD HH:MM or RFC3339)"))
	if err != nil {
		errMsg(err.Error())
		pause()
		return
	}
	if lastExpr.Matches(t) {
		okMsg("YES — the schedule fires at " + t.Format("2006-01-02 15:04:05 MST"))
	} else {
		warnMsg("NO — the schedule does not fire at " + t.Format("2006-01-02 15:04:05 MST"))
	}
	pause()
}

func tuiLint() {
	clear()
	banner()
	header("Lint & Normalize")
	if lastExpr == nil {
		warnMsg("parse an expression first (menu option 1)")
		pause()
		return
	}
	for _, l := range lintExpr(lastExpr) {
		info(l)
	}
	fmt.Println()
	okMsg("normalized: " + normalizeExpr(lastExpr))
	pause()
}

func tuiDST() {
	clear()
	banner()
	header("DST Transition Check")
	if lastExpr == nil {
		warnMsg("parse an expression first (menu option 1)")
		pause()
		return
	}
	loc := time.Local
	if tz := prompt("timezone (blank=local)"); tz != "" {
		if l, err := time.LoadLocation(tz); err == nil {
			loc = l
		} else {
			errMsg(err.Error())
			pause()
			return
		}
	}
	for _, l := range dstWarnings(lastExpr, loc) {
		if strings.HasPrefix(strings.TrimSpace(l), "→") {
			info(l)
		} else {
			warnMsg(l)
		}
	}
	pause()
}

// ---------------------------------------------------------------------------
// Help & Usage  (interactive menu [H])
// Page 1: in-app guide (what the tool does, every menu option, tips).
// Page 2: the full command-line reference (same text as --help).
// ---------------------------------------------------------------------------

type owlHelpItem struct{ key, text string }

func owlHelpWrap(s string, width int) []string {
	var out []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			out = append(out, "")
			continue
		}
		cur := ""
		for _, w := range words {
			if cur != "" && len([]rune(cur))+1+len([]rune(w)) > width {
				out = append(out, cur)
				cur = w
			} else if cur == "" {
				cur = w
			} else {
				cur += " " + w
			}
		}
		out = append(out, cur)
	}
	return out
}

func owlHelpTitle(t string) {
	fmt.Println()
	fmt.Println("  " + col("▸ "+t, B+CY))
}

func owlHelpPara(lines []string) {
	for _, l := range lines {
		for _, w := range owlHelpWrap(l, 60) {
			fmt.Println("    " + col(w, W))
		}
	}
}

func owlHelpRows(items []owlHelpItem) {
	kw := 0
	for _, it := range items {
		if n := len([]rune(it.key)); n > kw {
			kw = n
		}
	}
	for _, it := range items {
		k := "[" + it.key + "]" + strings.Repeat(" ", kw-len([]rune(it.key)))
		for i, w := range owlHelpWrap(it.text, 56-kw) {
			if i == 0 {
				fmt.Println("    " + col(k, YLW+B) + "  " + col(w, W))
			} else {
				fmt.Println("    " + strings.Repeat(" ", kw+2) + "  " + col(w, W))
			}
		}
	}
}

func owlHelpRule() { fmt.Println(col(strings.Repeat("─", 66), CY)) }

func tuiHelp() {
	clear()
	banner()
	owlHelpRule()
	fmt.Println("  " + col("⬡  Help & Usage — "+APPNAME, B+CY))
	owlHelpRule()
	owlHelpTitle("WHAT IT DOES")
	owlHelpPara(owlHelpAbout)
	owlHelpTitle("HOW TO USE THE MENU")
	owlHelpPara(owlHelpFlow)
	owlHelpTitle("MENU OPTIONS")
	owlHelpRows(owlHelpMenu)
	owlHelpTitle("TIPS")
	owlHelpRows(owlHelpTips)
	fmt.Println()
	owlHelpRule()
	fmt.Println("  " + col("Next page: command-line flags & copy-paste examples", DIM))
	pause()
	clear()
	owlHelpCLI()
	fmt.Println()
	fmt.Println("  " + col("Tip: the same reference is printed by  "+APPNAME+" --help", DIM))
	pause()
}

var owlHelpAbout = []string{
	"OCronGen builds, validates and explains cron schedules. It shows the next and previous run times in any timezone, audits whole crontab files for risky commands, converts schedules to systemd / Kubernetes / GitHub Actions / Quartz / Jenkins / AWS, and grades each expression.",
	"Standard 5-field cron (minute hour day-of-month month day-of-week), 6-field Quartz with seconds, and @macros (@daily, @hourly, @reboot ...) are all supported.",
}

var owlHelpFlow = []string{
	"Type the number of an option and press Enter. Most options work on the expression you parsed last, so start with [1] Parse & Explain. Every screen ends with \"Press Enter to continue\" and returns here. [H] opens this help, [0] or q quits.",
	"Field syntax: * = any value, 1,15 = list, 9-17 = range, */5 = every 5th. Names such as MON-FRI and JAN are allowed. Quartz mode adds L (last), W (weekday), # (nth weekday) and ?.",
}

var owlHelpMenu = []owlHelpItem{
	{"1", "Parse & Explain: enter an expression (e.g. */5 9-17 * * 1-5 or @daily). Answer y to allow Quartz specials. Shows a plain-English explanation, warnings, a grade and security findings. The expression is remembered for the other options."},
	{"2", "Next Runs: how many runs (blank = 10) and a timezone such as Europe/Berlin (blank = local). Needs [1] first."},
	{"3", "Previous Runs: how many past runs (blank = 5). Needs [1] first."},
	{"4", "Build Expression: enter each field one by one (minute, hour, day-of-month, month, day-of-week); blank = *. The result is parsed and remembered."},
	{"5", "Templates: list of ready-made schedules (nightly backup, business hours, ...). Use a name later with --template NAME."},
	{"6", "Macros: what @yearly, @monthly, @weekly, @daily, @hourly and @reboot expand to."},
	{"7", "Audit Crontab: give a crontab file path (e.g. /etc/crontab). Every line is parsed and its command is checked for curl|sh, base64 execution, reverse shells, chmod 777, rm -rf, hard-coded secrets and more."},
	{"8", "Overlap Check: enter several expressions, one per line, then an empty line. Shows times when two or more of them fire together."},
	{"9", "Random Expr: how many (blank = 5) valid random expressions, useful for testing."},
	{"10", "Field Reference: cheat-sheet of fields, allowed ranges and operators."},
	{"11", "Gap Stats: shortest / longest / average time between runs of the last expression."},
	{"12", "Calendar Heatmap: this month as a calendar showing how many runs fall on each day."},
	{"13", "Convert: choose systemd, quartz, k8s, actions, jenkins or aws to get the same schedule in that format."},
	{"14", "Diff: enter expression A and B to compare them field by field."},
	{"15", "Holiday Advice: warns when the schedule fires on common public holidays."},
	{"16", "Count In Range: give a from and a to date (YYYY-MM-DD or RFC3339) and get the number of runs between them."},
	{"17", "Fires At?: give a date and time (YYYY-MM-DD HH:MM) and see whether the schedule runs at that minute."},
	{"18", "Lint / Normalize: style and safety suggestions plus the shortest canonical form of the expression."},
	{"19", "DST Check: give a timezone; shows runs that are skipped or repeated when the clocks change."},
	{"20", "Validation Corpus: runs the built-in set of known-good and known-bad expressions."},
	{"21", "Export Report: choose txt, md, json, csv or sarif and an output file (blank = print to screen) to save the last report."},
	{"22", "Self-Test: runs the internal self-tests to confirm the tool works correctly."},
}

var owlHelpTips = []owlHelpItem{
	{"*", "Cron uses the server's local time unless you pick a timezone, so check Next Runs with the timezone of the machine that will run the job."},
	{"*", "If both day-of-month and day-of-week are set (not *), cron runs when EITHER matches, not both."},
	{"*", "Use the command line for scripts and CI: --expr, --crontab and --format json/sarif (next page)."},
}

func owlHelpCLI() { usage() }
