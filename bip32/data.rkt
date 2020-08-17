#lang typed/racket

(require ec)

(provide (struct-out xmeta)
         (struct-out xpriv)
         (struct-out xpub)
         ver-xprv
         ver-xpub
         ver-tprv
         ver-tpub)

(struct xmeta
  ([version : Bytes]
   [depth : Byte]
   [parent-fingerprint : Bytes]
   [child-index : Nonnegative-Integer]
   [chain-code : Bytes])
  #:transparent)

(struct xpriv xmeta
  ([exponent : Nonnegative-Integer])
  #:transparent)

(struct xpub xmeta
  ([point : jacobian-point])
  #:transparent)

(define ver-xprv #"\4\210\255\344")
(define ver-xpub #"\4\210\262\36")
(define ver-tprv #"\0045\203\224")
(define ver-tpub #"\0045\207\317")
