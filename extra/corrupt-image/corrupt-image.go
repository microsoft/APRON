// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
package main

import (
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"time"
)

const DataBlockSize = 1048576 // 1 MiB

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	if len(os.Args) != 4 {
		fmt.Printf("Usage: %s <input> <output> <threshold>\n", os.Args[0])
		os.Exit(1)
	}

	f, err := os.Open(os.Args[1])
	check(err)

	fout, err := os.Create(os.Args[2])
	check(err)

	t, err := strconv.Atoi(os.Args[3])
	check(err)

	fstat, err := f.Stat()
	check(err)

	length := fstat.Size() / DataBlockSize
	bufzero := make([]byte, DataBlockSize)
	buf := make([]byte, DataBlockSize)

	s := rand.NewSource(time.Now().UnixNano())
	r := rand.New(s)

	for i := int64(0); i < length; i++ {
		n, _ := f.Read(buf)
		if n != DataBlockSize {
			break
		}

		if i == 0 {
			fout.Write(bufzero)
			continue
		}

		if r.Intn(100) <= t {
			fout.Write(bufzero)
		} else {
			fout.Write(buf)
		}
	}
}
