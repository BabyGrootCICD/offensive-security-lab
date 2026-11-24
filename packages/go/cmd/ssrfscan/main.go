package main

import (
	"flag"
	"fmt"
	"os"

	"offensive-security-lab/packages/go/internal/report"
	"offensive-security-lab/packages/go/internal/rules"
	"offensive-security-lab/packages/go/internal/scan"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "ssrfscan: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("ssrfscan", flag.ContinueOnError)
	path := fs.String("path", "", "要掃描的檔案或目錄")
	rulesPath := fs.String("rules", "", "規則 JSON 路徑")
	jsonOut := fs.String("json-out", "", "JSON 報告輸出路徑")
	mdOut := fs.String("md-out", "", "Markdown 報告輸出路徑")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" || *rulesPath == "" {
		return fmt.Errorf("需要 --path 與 --rules")
	}
	ruleSet, err := rules.Load(*rulesPath)
	if err != nil {
		return err
	}
	findings, err := scan.Scan(*path, ruleSet)
	if err != nil {
		return err
	}
	doc := report.New("go", findings)
	if *jsonOut == "" && *mdOut == "" {
		return report.WriteJSON(os.Stdout, doc)
	}
	if *jsonOut != "" {
		if err := writeFile(*jsonOut, func(file *os.File) error { return report.WriteJSON(file, doc) }); err != nil {
			return err
		}
	}
	if *mdOut != "" {
		if err := writeFile(*mdOut, func(file *os.File) error { return report.WriteMarkdown(file, doc) }); err != nil {
			return err
		}
	}
	return nil
}

func writeFile(path string, write func(*os.File) error) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer file.Close()
	if err := write(file); err != nil {
		return err
	}
	return file.Close()
}
