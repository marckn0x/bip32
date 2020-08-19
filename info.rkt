#lang setup/infotab
(define version "0.1.1")
(define collection 'multi)
(define deps '("base"
               "binaryio"
               "sha"
               "crypto"
               "base58"
               "ec"
               "typed-racket-lib"))
(define build-deps '("racket-doc"
                     "rackunit-lib"
                     "scribble-lib"
                     "rackunit-typed"))
