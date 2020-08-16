#lang typed/racket

(require ecc
         base58
         "typed-sha.rkt"
         "typed-binaryio.rkt"
         "ripemd160.rkt")

(provide (struct-out xmeta)
         (struct-out xpriv)
         (struct-out xpub)
         CKDpriv
         CKDpub
         N
         parse-xpub
         serialize-xpub
         parse-xpriv
         serialize-xpriv
         xpub-derive-path
         xpriv-derive-path
         parse-path-string)

(struct xmeta
  ([version : Bytes]
   [depth : Byte]
   [parent-fp : Bytes]
   [child-num : Nonnegative-Integer]
   [c : Bytes])
  #:transparent)

(struct xpriv xmeta
  ([k : Nonnegative-Integer])
  #:transparent)

(struct xpub xmeta
  ([k : jacobian-point])
  #:transparent)

(: fingerprint (-> Bytes Bytes))
(define (fingerprint sec-bytes)
  (subbytes (ripemd160 (sha256 sec-bytes)) 0 4))

(: CKDpriv (-> xpriv Nonnegative-Integer xpriv))
(define (CKDpriv x i)
  (match-define (xpriv v d _ _ c k) x)
  (define public-sec (point->sec (jacobian->affine (dG secp256k1 k))))
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
  (when (>= i (expt 2 31))
    (raise "attempted CKDpub with a hardened child index"))
  (define public-sec (point->sec (jacobian->affine k)))
  (define I (hmac-sha512 c (bytes-append public-sec (integer->bytes i 4 #f #t))))
  (xpub
   v
   (assert (min (add1 d) 255) byte?)
   (fingerprint public-sec)
   i
   (subbytes I 32)
   (ec+ (dG secp256k1 (bytes->integer (subbytes I 0 32) #f #t)) k)))

(define ver-xprv #"\4\210\255\344")
(define ver-xpub #"\4\210\262\36")
(define ver-tprv #"\0045\203\224")
(define ver-tpub #"\0045\207\317")

(: pub-version (-> Bytes Bytes))
(define (pub-version v)
  (match v
    [ver-xpriv ver-xpub]
    [ver-tprv  ver-tpub]
    [_ (raise (format "Invalid private version bytes: ~a" v))]))

(: N (-> xpriv xpub))
(define (N x)
  (match-define (xpriv v d fp cn c k) x)
  (xpub
   (pub-version v) d fp cn c
   (dG secp256k1 k)))

(: parse-xmeta (-> String (Values xmeta Bytes)))
(define (parse-xmeta str)
  (define bs (base58-decode str))
  (values
   (xmeta
    (subbytes bs 0 4)
    (bytes-ref bs 4)
    (subbytes bs 5 9)
    (bytes->integer (subbytes bs 9 13) #f #t)
    (subbytes bs 13 45))
   (subbytes bs 45)))

(: encode-xmeta (-> xmeta Bytes))
(define (encode-xmeta xm)
  (bytes-append
   (xmeta-version xm)
   (bytes (xmeta-depth xm))
   (xmeta-parent-fp xm)
   (integer->bytes (xmeta-child-num xm) 4 #f #t)
   (xmeta-c xm)))

(: parse-xpub (-> String xpub))
(define (parse-xpub str)
  (define-values (xm rest) (parse-xmeta str))
  (match (xmeta-version xm)
    [(or (== ver-xpub) (== ver-tpub))
     (xpub (xmeta-version xm)
           (xmeta-depth xm)
           (xmeta-parent-fp xm)
           (xmeta-child-num xm)
           (xmeta-c xm)
           (affine->jacobian (sec->point secp256k1 rest)))]
    [v (raise (format "Invalid version bytes for xpub: ~a" v))]))

(: serialize-xpub (-> xpub String))
(define (serialize-xpub x)
  (base58-encode
   (bytes-append
    (encode-xmeta x)
    (point->sec (jacobian->affine (xpub-k x))))))

(: parse-xpriv (-> String xpriv))
(define (parse-xpriv str)
  (define-values (xm rest) (parse-xmeta str))
  (match (xmeta-version xm)
    [(or (== ver-xprv) (== ver-tprv))
     (xpriv (xmeta-version xm)
            (xmeta-depth xm)
            (xmeta-parent-fp xm)
            (xmeta-child-num xm)
            (xmeta-c xm)
            (bytes->integer rest #f #t))]
    [v (raise (format "Invalid version bytes for xpriv: ~a" v))]))

(: serialize-xpriv (-> xpriv String))
(define (serialize-xpriv x)
  (base58-encode
   (bytes-append
    (encode-xmeta x)
    #"\0"
    (integer->bytes (xpriv-k x) 32 #f #t))))

(: derive-path (All (A) (-> (-> A Nonnegative-Integer A) A (Listof Nonnegative-Integer) A)))
(define (derive-path step root path)
  (let loop ([key root]
             [path path])
    (if (empty? path)
        key
        (loop (step key (first path)) (rest path)))))

(: xpub-derive-path (-> xpub (Listof Nonnegative-Integer) xpub))
(define (xpub-derive-path root path) (derive-path CKDpub root path))

(: xpriv-derive-path (-> xpriv (Listof Nonnegative-Integer) xpriv))
(define (xpriv-derive-path root path) (derive-path CKDpriv root path))

(: parse-path-string (-> String (Listof Nonnegative-Integer)))
(define (parse-path-string str)
  (match (string-split str "/")
    [(list "m" (regexp #rx"^(0|[1-9][0-9]*)([hH'*])?$" (list _ idxs hards)) ...)
     (for/list ([idx idxs] [hard hards])
       (assert idx string?)
       (+ (assert (string->number idx) exact-nonnegative-integer?)
          (if hard (expt 2 31) 0)))]
    [_ (error (format "Invalid bip32 path string: ~a" str))]))
