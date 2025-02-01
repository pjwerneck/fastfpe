extern crate bencher;

fn context(b: &mut bencher::Bencher) {
    b.iter(|| {
        fpe::ff3_1::FF3_1::new(&[0; 32], Some(&[0; 7]), 26, None).unwrap()
    });
}

fn encrypt(b: &mut bencher::Bencher) {
    let ff3_1 =
        fpe::ff3_1::FF3_1::new(&[0; 32], Some(&[0; 7]), 26, None).unwrap();
    b.iter(|| ff3_1.encrypt("0123456789", None));
}

fn decrypt(b: &mut bencher::Bencher) {
    let ff3_1 =
        fpe::ff3_1::FF3_1::new(&[0; 32], Some(&[0; 7]), 26, None).unwrap();
    let ct = ff3_1.encrypt("0123456789", None).unwrap();
    b.iter(|| ff3_1.decrypt(&ct, None));
}

bencher::benchmark_group!(benches, context, encrypt, decrypt);
bencher::benchmark_main!(benches);
