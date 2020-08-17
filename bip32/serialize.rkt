#lang typed/racket

(require "data.rkt"
         "typed-binaryio.rkt"
         base58
         ec)

(provide string->xpub
         xpub->string
         string->xpriv
         xpriv->string)

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
   (xmeta-parent-fingerprint xm)
   (integer->bytes (xmeta-child-index xm) 4 #f #t)
   (xmeta-chain-code xm)))

(: string->xpub (-> String xpub))
(define (string->xpub str)
  (define-values (xm rest) (parse-xmeta str))
  (match (xmeta-version xm)
    [(or (== ver-xpub) (== ver-tpub))
     (xpub (xmeta-version xm)
           (xmeta-depth xm)
           (xmeta-parent-fingerprint xm)
           (xmeta-child-index xm)
           (xmeta-chain-code xm)
           (affine->jacobian (sec->point secp256k1 rest)))]
    [v (raise (format "Invalid version bytes for xpub: ~a" v))]))

(: xpub->string (-> xpub String))
(define (xpub->string x)
  (base58-encode
   (bytes-append
    (encode-xmeta x)
    (point->sec (jacobian->affine (xpub-point x))))))

(: string->xpriv (-> String xpriv))
(define (string->xpriv str)
  (define-values (xm rest) (parse-xmeta str))
  (match (xmeta-version xm)
    [(or (== ver-xprv) (== ver-tprv))
     (xpriv (xmeta-version xm)
            (xmeta-depth xm)
            (xmeta-parent-fingerprint xm)
            (xmeta-child-index xm)
            (xmeta-chain-code xm)
            (bytes->integer rest #f #t))]
    [v (raise (format "Invalid version bytes for xpriv: ~a" v))]))

(: xpriv->string (-> xpriv String))
(define (xpriv->string x)
  (base58-encode
   (bytes-append
    (encode-xmeta x)
    #"\0"
    (integer->bytes (xpriv-exponent x) 32 #f #t))))
