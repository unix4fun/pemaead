# pemaead
A simple PEM enveloppe using AES AEAD encryption mode go package/library.

## Purpose
a simple io.ReadCloser / io.WriteCloser interface, to store and encrypt/tag a reasonnably small amount of data at rest, 
an attempt to be reasonnably resistant to offline attacks as well as ensure data + header integrity using an "encrypt-then-MAC" 
approach (thanks to AEAD and trying to avoid Encrypt-and-MAC and MAC-then-encrypt kind of schemes).

Relying on AEAD properties to ensure integrity of data + headers (+ CSRNG key derivation salt & AEAD nonce).

Key is derivated using strong derivation functions trying to slow down brute-force:
* Scrypt
* Argon2id
* PBKDF2 (if standard is needed)

Using AES-GCM-256 encryption mode & Argon2id key derivation by default, a random salt & nonce.

## Usage Examples

Important notes:
* Write() is only buffering, the call to Close() will actually write your data, keep that in mind.
* Close() will close the underlying fd provided to the Writer.
  
### Writer
    ...
    fd, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY|os.O_EXCL|os.O_SYNC, 0700)
    if err != nil {
      return err
    }
  
    pemfd, err := pemaead.NewWriter(fd, password, pemaead.CipherAESGCM, pemaead.DerivateArgon2)
    if err != nil {
      return err
    }
    defer pemfd.Close()
    ...
    _, err = pemfd.Write(data)
    if err != nil {
      return err
    }
    ...
  
### Reader
    ...
    fd, err := os.Open(fileName)
		if err != nil {
			return err
		}
		defer fd.Close()
		
		pemfd, err := pemaead.NewReader(fd, password)
		if err != nil {
			return err
		}
		
		data, err := ioutil.ReadAll(pemfd)
		if err != nil {
			return err
		}


## TODO
* go docs
* unit tests
* more clearly define limitations
* add PQ algorithms
* add other AEAD algorithms.

## ChangeLog

* 2018-07-20
  * v0.1.0 : initial release/push outside the realm of my own usage to the world :)
