#lang typed/racket

(module untyped racket
  (require crypto
           crypto/libcrypto)
  
  (provide ripemd160)

  (define (ripemd160 msg)
    (parameterize ([crypto-factories (list libcrypto-factory)])
      (define ctx (make-digest-ctx 'ripemd160))
      (digest-update ctx msg)
      (digest-final ctx))))

(require/typed/provide
 'untyped
 [ripemd160 (-> Bytes Bytes)])
