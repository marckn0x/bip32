#lang typed/racket

(require "derive.rkt"
         "data.rkt")

(provide xpub-derive-path
         xpriv-derive-path
         string->path)

(: derive-path (All (A) (-> (-> A Nonnegative-Integer A) A (Listof Nonnegative-Integer) A)))
(define (derive-path step root path)
  (for/fold ([key root]) ([elem : Nonnegative-Integer path]) (step key elem)))

(: xpub-derive-path (-> xpub (Listof Nonnegative-Integer) xpub))
(define (xpub-derive-path root path) (derive-path CKDpub root path))

(: xpriv-derive-path (-> xpriv (Listof Nonnegative-Integer) xpriv))
(define (xpriv-derive-path root path) (derive-path CKDpriv root path))

(: string->path (-> String (Listof Nonnegative-Integer)))
(define (string->path str)
  (match (string-split str "/")
    [(list "m" (regexp #rx"^(0|[1-9][0-9]*)([hH'*])?$" (list _ idxs hards)) ...)
     (for/list ([idx idxs] [hard hards])
       (assert idx string?)
       (+ (assert (string->number idx) exact-nonnegative-integer?)
          (if hard (expt 2 31) 0)))]
    [_ (error (format "Invalid bip32 path string: ~a" str))]))
