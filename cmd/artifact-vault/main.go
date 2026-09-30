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
		return fmt.Errorf("usage: artifact-vault <init|put|get|list|verify>")
	}
	command := args[0]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	root := flags.String("root", "./vault", "vault directory")
	name := flags.String("name", "", "logical artifact name")
	file := flags.String("file", "", "input file")
	output := flags.String("output", "", "output file")
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
	default:
		return fmt.Errorf("unknown command %q", command)
	}
}
