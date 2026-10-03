package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Hulalalalalalalalalalala/artifact-vault/internal/vault"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: artifact-vault <init|put|get|list|verify|snapshot|gc>")
	}
	command := args[0]
	if command == "snapshot" {
		return runSnapshot(args[1:])
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	root := flags.String("root", "./vault", "vault directory")
	name := flags.String("name", "", "logical artifact name")
	file := flags.String("file", "", "input file")
	output := flags.String("output", "", "output file")
	dryRun := flags.Bool("dry-run", false, "preview garbage collection without deleting anything")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	store := vault.New(*root)
	switch command {
	case "init":
		return store.Init()
	case "put":
		entry, err := store.Put(*name, *file)
		if err == nil {
			fmt.Printf("stored %s sha256=%s size=%d\n", entry.Name, entry.Digest, entry.Size)
		}
		return err
	case "get":
		return store.Get(*name, *output)
	case "list":
		entries, err := store.List()
		if err != nil {
			return err
		}
		for _, entry := range entries {
			fmt.Printf("%s\t%s\t%d\n", entry.Name, entry.Digest, entry.Size)
		}
		return nil
	case "verify":
		count, err := store.Verify()
		if err == nil {
			fmt.Printf("verified %d artifacts\n", count)
		}
		return err
	case "gc":
		report, err := store.GC(*dryRun)
		if err != nil {
			return err
		}
		if *dryRun {
			var bytes int64
			for _, candidate := range report.Candidates {
				fmt.Printf("%s\t%d\n", candidate.Digest, candidate.Size)
				bytes += candidate.Size
			}
			fmt.Printf("total %d objects, %d bytes\n", len(report.Candidates), bytes)
			return nil
		}
		fmt.Printf("deleted %d objects, %d bytes\n", report.Deleted, report.Bytes)
		return nil
	default:
		return fmt.Errorf("unknown command %q", command)
	}
}

func runSnapshot(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: artifact-vault snapshot <create|list|restore|export|import> --root <dir> [flags]")
	}
	sub := args[0]
	flags := flag.NewFlagSet("snapshot "+sub, flag.ContinueOnError)
	root := flags.String("root", "./vault", "vault directory")
	name := flags.String("name", "", "snapshot name")
	base := flags.String("base", "", "base snapshot for an incremental export")
	file := flags.String("file", "", "package file to import")
	output := flags.String("output", "", "package file to write")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	store := vault.New(*root)
	switch sub {
	case "create":
		// Creation validates the current mapping and writes the record; a
		// successful run prints nothing, while a failure is reported on
		// stderr via run's error handling.
		_, err := store.CreateSnapshot(*name)
		return err
	case "list":
		infos, err := store.ListSnapshots()
		if err != nil {
			return err
		}
		for _, info := range infos {
			fmt.Printf("%s\t%d\n", info.Name, info.Count)
		}
		return nil
	case "restore":
		if err := store.RestoreSnapshot(*name); err != nil {
			return err
		}
		fmt.Printf("restored snapshot %s\n", *name)
		return nil
	case "export":
		result, err := store.ExportSnapshot(*name, *base, *output)
		if err != nil {
			return err
		}
		fmt.Printf("exported snapshot %s with %d entries, %d objects\n", result.Name, result.Entries, result.Objects)
		return nil
	case "import":
		result, err := store.ImportSnapshot(*file)
		if err != nil {
			return err
		}
		fmt.Printf("imported snapshot %s with %d entries, %d new objects\n", result.Name, result.Entries, result.NewObjects)
		return nil
	default:
		return fmt.Errorf("unknown snapshot command %q", sub)
	}
}
