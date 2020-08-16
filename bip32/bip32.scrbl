#lang scribble/manual

@(require (for-label racket))

@title{BIP-32}

@defmodule[bip32]

Provides Racket implementations of Bitcoin Improvement Proposal 32.

@section{Extended Keys}

@defstruct[xmeta ([version bytes?]
                  [depth byte?]
                  [parent-fp bytes?]
                  [child-num exact-nonnegative-integer?]
                  [c bytes?])]{
Public or private extended key metadata.
}
