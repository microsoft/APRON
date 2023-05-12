use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::io::{BufReader, BufWriter};

const BLOCK_SIZE: usize = 4096;

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() != 4 {
        let prog = ::std::env::args().nth(0).unwrap();
        println!("Usage: {} new-image old-image output", prog);
        return;
    }

    let in_new = ::std::env::args().nth(1).unwrap();
    let in_old = ::std::env::args().nth(2).unwrap();
    let output = ::std::env::args().nth(3).unwrap();

    let fin_new = File::open(in_new).expect("not found");
    let fin_old = File::open(in_old).expect("not found");
    let fout = File::create(output).expect("failed to create");

    let mut reader_new = BufReader::new(fin_new);
    let mut reader_old = BufReader::new(fin_old);
    let mut writer = BufWriter::new(fout);

    let mut buf_new = [0u8; BLOCK_SIZE];
    let mut buf_old = [0u8; BLOCK_SIZE];

    let mut count = 0;
    let mut byte = [0u8; 1];
    let mut bytewritten = 0;
    loop {
        let byteread_new = reader_new.read(&mut buf_new).unwrap();
        if byteread_new == 0 {
            break;
        }

        let byteread_old = reader_old.read(&mut buf_old).unwrap();
        if byteread_old == 0 {
            break;
        }

        if buf_new == buf_old {
            byte[0] = byte[0] << 1;
        } else {
            byte[0] = (byte[0] << 1) | 1;
        }

        count += 1;
        if count == 8 {
            writer.write(&byte).expect("write error");
            bytewritten += 1;
            count = 0;
            byte[0] = 0;
        }
    }

    loop {
        let byteread_new = reader_new.read(&mut buf_new).unwrap();
        if byteread_new == 0 {
            break;
        }

        count += 1;
        if count == 8 {
            writer.write(&byte).expect("write error");
            bytewritten += 1;
            count = 0;
        }
    }

    if count != 0 {
        byte[0] = byte[0] << (8 - count);
        writer.write(&byte).expect("write error");
        bytewritten += 1;
    }

    if bytewritten % BLOCK_SIZE != 0 {
        byte[0] = 0;
        loop {
            writer.write(&byte).expect("write error");
            bytewritten += 1;

            if bytewritten % BLOCK_SIZE == 0 {
                break;
            }
        }
    }
}
