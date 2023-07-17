// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
)

const DataBlockSize = 4096

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <zerofree-ed device>\n", os.Args[0])
		os.Exit(1)
	}

	f, err := os.Open(os.Args[1])
	check(err)

	f_stat, err := f.Stat()
	check(err)

	length := f_stat.Size()/DataBlockSize + f_stat.Size()%DataBlockSize
	zeros := make([]bool, length)

	bufzero := make([]byte, DataBlockSize)
	buf := make([]byte, DataBlockSize)

	for i := int64(0); i < length; i++ {
		n, _ := f.Read(buf)
		if n != DataBlockSize {
			break
		}

		if bytes.Compare(bufzero, buf) == 0 {
			zeros[i] = true
		} else {
			zeros[i] = false
		}
	}

	for i := int64(0); i < length; i += 8 {
		num := uint8(0)
		for j := int64(0); j < 8; j++ {
			if zeros[i+j] == true {
				num |= (1 << j)
			}
		}
		binary.Write(os.Stdout, binary.LittleEndian, num)
	}
}
