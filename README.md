# django-signing-rust

This crate implements
[Django's](https://docs.djangoproject.com/en/4.0/topics/signing/) cryptographic
signing of strings and objects for Rust.

```rust
use serde::{Deserialize, Serialize};
use django_signing;

const SECRET: &[u8] = b"my-secret-key";
const SALT: &[u8] = b"demo-salt";

#[derive(Debug, Serialize, Deserialize)]
struct Book {
    title: String,
    author: String,
    year: u16,
}

let book = Book {
    title: String::from("The Lord of the Rings"),
    author: String::from("J. R. R. Tolkien"),
    year: 1954,
};

let compress = true;
let signed = django_signing::dumps(book, SECRET, SALT, compress);

println!("Signed value: {}", signed);
// This prints something like:
// Signed value: eyJ0aXRsZSI6IlRoZSBMb3JkIG9mIHRoZSBSaW5ncyIsImF1dGhvciI6IkouIFIuIFIuIFRvbGtpZW4iLCJ5ZWFyIjoxOTU0fQ:1n5aMt:Q7rI7rBXrLmMFsxLPnkiLl1GCr_ygqsM0nHBkazgvYc

let unsigned: Book = django_signing::loads(
    signed, SECRET, SALT,
    // Signature expires after 60 seconds
    django_signing::Duration::new(60, 0)
).unwrap();

println!("Unsigned value: {:?}", unsigned);
// This prints:
// Unsigned value: Book { title: "The Lord of the Rings", author: "J. R. R. Tolkien", year: 1954 }
```

There's also access to the `BaseSigner` and `TimestampSigner` structs which
relate to Django's
[`Signer`](https://docs.djangoproject.com/en/4.0/topics/signing/#django.core.signing.Signer)
and
[`TimestampSigner`](https://docs.djangoproject.com/en/4.0/topics/signing/#django.core.signing.TimestampSigner)
classes, respectively.

The library only supports SHA-256, since SHA-1 is typically a bad idea these days!
