mod tests {
    mod ff1 {
        use fpe::result::Result;

        fn test_ff1(
            k: &[u8],
            opt_t: Option<&[u8]>,
            pt: &str,
            ct: &str,
            r: usize,
            opt_a: Option<&str>,
        ) -> Result<()> {
            let ff1 = fpe::ff1::FF1::new(k, opt_t, 0, 0, r, opt_a)?;

            let out = ff1.encrypt(pt, None)?;
            assert!(ct == out, "encrypt: \"{}\" != \"{}\"", ct, out);

            let out = ff1.decrypt(ct, None)?;
            assert!(pt == out, "decrypt: \"{}\" != \"{}\"", pt, out);

            assert!(ct == fpe::ff1::encrypt(k, opt_t, pt, r, opt_a)?);
            assert!(pt == fpe::ff1::decrypt(k, opt_t, ct, r, opt_a)?);

            Ok(())
        }

        #[test]
        fn nist1() -> Result<()> {
            test_ff1(
                &[
                    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7,
                    0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
                ],
                None,
                "0123456789",
                "2433477484",
                10,
                None,
            )
        }

        #[test]
        fn nist2() -> Result<()> {
            test_ff1(
                &[
                    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7,
                    0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
                ],
                Some(&[
                    0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30,
                ]),
                "0123456789",
                "6124200773",
                10,
                None,
            )
        }

        #[test]
        fn nist3() -> Result<()> {
            test_ff1(
                &[
                    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7,
                    0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
                ],
                Some(&[
                    0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37,
                    0x37,
                ]),
                "0123456789abcdefghi",
                "a9tv40mll9kdu509eum",
                36,
                None,
            )
        }

        #[test]
        fn nist4() -> Result<()> {
            test_ff1(
                &[
                    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7,
                    0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c, 0xef, 0x43, 0x59, 0xd8,
                    0xd5, 0x80, 0xaa, 0x4f,
                ],
                None,
                "0123456789",
                "2830668132",
                10,
                None,
            )
        }

        #[test]
        fn nist5() -> Result<()> {
            test_ff1(
                &[
                    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7,
                    0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c, 0xef, 0x43, 0x59, 0xd8,
                    0xd5, 0x80, 0xaa, 0x4f,
                ],
                Some(&[
                    0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30,
                ]),
                "0123456789",
                "2496655549",
                10,
                None,
            )
        }

        #[test]
        fn nist6() -> Result<()> {
            test_ff1(
                &[
                    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7,
                    0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c, 0xef, 0x43, 0x59, 0xd8,
                    0xd5, 0x80, 0xaa, 0x4f,
                ],
                Some(&[
                    0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37,
                    0x37,
                ]),
                "0123456789abcdefghi",
                "xbj3kv35jrawxv32ysr",
                36,
                None,
            )
        }

        #[test]
        fn nist7() -> Result<()> {
            test_ff1(
                &[
                    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7,
                    0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c, 0xef, 0x43, 0x59, 0xd8,
                    0xd5, 0x80, 0xaa, 0x4f, 0x7f, 0x03, 0x6d, 0x6f, 0x04, 0xfc,
                    0x6a, 0x94,
                ],
                None,
                "0123456789",
                "6657667009",
                10,
                None,
            )
        }

        #[test]
        fn nist8() -> Result<()> {
            test_ff1(
                &[
                    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7,
                    0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c, 0xef, 0x43, 0x59, 0xd8,
                    0xd5, 0x80, 0xaa, 0x4f, 0x7f, 0x03, 0x6d, 0x6f, 0x04, 0xfc,
                    0x6a, 0x94,
                ],
                Some(&[
                    0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30,
                ]),
                "0123456789",
                "1001623463",
                10,
                None,
            )
        }

        #[test]
        fn nist9() -> Result<()> {
            test_ff1(
                &[
                    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7,
                    0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c, 0xef, 0x43, 0x59, 0xd8,
                    0xd5, 0x80, 0xaa, 0x4f, 0x7f, 0x03, 0x6d, 0x6f, 0x04, 0xfc,
                    0x6a, 0x94,
                ],
                Some(&[
                    0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37,
                    0x37,
                ]),
                "0123456789abcdefghi",
                "xs8a0azh2avyalyzuwd",
                36,
                None,
            )
        }
    }
}
