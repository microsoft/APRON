use byteorder::{ByteOrder, LittleEndian};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::io::{BufReader, BufWriter};

const BLOCK_SIZE: usize = 4096;

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() != 3 {
        let prog = ::std::env::args().nth(0).unwrap();
        println!("Usage: {} raw-image output", prog);
        return;
    }
    let input = ::std::env::args().nth(1).unwrap();
    let output = ::std::env::args().nth(2).unwrap();
    let fin = File::open(input).expect("not found");
    let fout = File::create(output).expect("failed to create");
    let mut reader = BufReader::new(fin);
    let mut writer = BufWriter::new(fout);

    let bufzero = [0u8; BLOCK_SIZE];
    let mut buf = [0u8; BLOCK_SIZE];

    let mut blockset = HashMap::new();

    let mut blocknr = 0;
    loop {
        let byteread = reader.read(&mut buf).unwrap();
        if byteread == 0 {
            break;
        }

        if buf == bufzero {
            blocknr += 1;
            continue;
        }

        let mut hasher = Sha256::new();
        hasher.update(buf);
        let digest = hasher.finalize();

        if blockset.get(&digest) == None {
            blockset.insert(digest, Vec::new());
        }
        blockset.get_mut(&digest).unwrap().push(blocknr);
        blocknr += 1;
    }

    let mut blockpairs = HashMap::new();
    for (_digest, vec) in &blockset {
        if vec.len() == 1 {
            continue;
        }

        for x in vec.iter() {
            blockpairs.insert(x, vec[0]);
        }
    }

    let mut keys = Vec::new();
    for (k, _) in blockpairs.iter() {
        keys.push(k);
    }
    keys.sort();

    let mut buf = [0u8; 4];
    for k in keys {
        LittleEndian::write_i32(&mut buf, **k as i32);
        writer.write(&buf).expect("write error");

        LittleEndian::write_i32(&mut buf, blockpairs[k] as i32);
        writer.write(&buf).expect("write error");
    }
}
