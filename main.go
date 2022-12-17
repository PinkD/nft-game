package main

import (
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/spf13/pflag"
)

var exit bool

func main() {
	confPath := pflag.StringP("wg-conf", "c", "", "wireguard.conf")
	driverName := pflag.StringP("driver-name", "n", "netfilter2", "driver name")
	processPath := pflag.StringSliceP("file", "f", nil, "multi process files or single directory")
	pflag.Parse()
	if len(*confPath) == 0 || len(*processPath) == 0 {
		pflag.Usage()
		return
	}

	wgConf, err := ParseWgConf(*confPath)
	if err != nil {
		panic(err)
	}
	if len(*processPath) == 0 {
		panic("no process file provided")
	}
	var processFiles []string
	switch {
	case len(*processPath) == 1:
		file := (*processPath)[0]
		fi, err := os.Stat(file)
		if os.IsNotExist(err) {
			// if path not exist, we treat it as process name
			processFiles = append(processFiles, file)
			break
		}
		if err != nil {
			panic(err)
		}
		if fi.IsDir() {
			err := filepath.WalkDir(file, func(path string, d fs.DirEntry, err error) error {
				if !d.IsDir() {
					if filepath.Ext(file) == "exe" {
						file = filepath.Base(file)
						processFiles = append(processFiles, file)
					}
				}
				return nil
			})
			if err != nil {
				return
			}
		} else {
			processFiles = append(processFiles, file)
		}
	default:
		for _, s := range *processPath {
			processFiles = append(processFiles, s)
		}
	}
	conf := &Conf{
		WgConf:       wgConf,
		processNames: processFiles,
	}
	nf := NewNetFilter(*driverName, conf)
	err = nf.Start()
	if err != nil {
		panic(err)
	}
	defer nf.Stop()
	stopChan := make(chan os.Signal)
	signal.Notify(stopChan, os.Interrupt, os.Kill)
	<-stopChan
}
