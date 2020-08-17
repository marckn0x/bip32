#lang typed/racket

(require ec
         base58
         "data.rkt"
         "ripemd160.rkt"
         "typed-binaryio.rkt")

(require/typed
 sha
 [hmac-sha512 (-> Bytes Bytes Bytes)]
 [sha256 (-> Bytes Bytes)])

(provide CKDpriv
         CKDpub
         N)

(: fingerprint (-> Bytes Bytes))
(define (fingerprint sec-bytes)
  (subbytes (ripemd160 (sha256 sec-bytes)) 0 4))

(: CKDpriv (-> xpriv Nonnegative-Integer xpriv))
(define (CKDpriv x i)
  (match-define (xpriv v d _ _ c k) x)
  (define public-sec (point->sec (jacobian->affine (dG secp256k1 k))))
  (unless (< i (expt 2 32))
    (error "child index is too large"))
  (define I
    (if (>= i (expt 2 31))
        (hmac-sha512
         c
         (bytes-append (bytes 0) (integer->bytes k 32 #f #t) (integer->bytes i 4 #f #t)))
        (hmac-sha512
         c
         (bytes-append public-sec (integer->bytes i 4 #f #t)))))
  (xpriv
   v
   (assert (min (add1 d) 255) byte?)
   (fingerprint public-sec)
   i
   (subbytes I 32)
   (modulo (+ (bytes->integer (subbytes I 0 32) #f #t) k) (curve-n secp256k1))))

(: CKDpub (-> xpub Nonnegative-Integer xpub))
(define (CKDpub x i)
  (match-define (xpub v d _ _ c k) x)
  (unless (< i (expt 2 32))
    (error "child index is too large"))
  (when (>= i (expt 2 31))
    (error "attempted CKDpub with a hardened child index"))
  (define public-sec (point->sec (jacobian->affine k)))
  (define I (hmac-sha512 c (bytes-append public-sec (integer->bytes i 4 #f #t))))
  (xpub
   v
   (assert (min (add1 d) 255) byte?)
   (fingerprint public-sec)
   i
   (subbytes I 32)
   (ec+ (dG secp256k1 (bytes->integer (subbytes I 0 32) #f #t)) k)))

(: pub-version (-> Bytes Bytes))
(define (pub-version v)
  (match v
    [ver-xpriv ver-xpub]
    [ver-tprv  ver-tpub]
    [_ (error (format "Invalid private version bytes: ~a" v))]))

(: N (-> xpriv xpub))
(define (N x)
  (match-define (xpriv v d fp cn c k) x)
  (xpub
   (pub-version v) d fp cn c
   (dG secp256k1 k)))
