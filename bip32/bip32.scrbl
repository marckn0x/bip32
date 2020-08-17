#lang scribble/manual

@(require (for-label racket)
          (for-label ec))

@title{BIP-32}

@author[(author+email "Marc Burns" "marc@kn0x.io")]

@defmodule[bip32]

Provides a Racket implementation of
@hyperlink["https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki"]{Bitcoin Improvement Proposal 32}.

@section{Extended Keys}

@defstruct*[xmeta ([version bytes?]
                   [depth byte?]
                   [parent-fingerprint bytes?]
                   [child-index exact-nonnegative-integer?]
                   [chain-code bytes?])]{
 Extended public or private key metadata.
}

@defstruct*[xpub ([point jacobian-point?])]{
 Extended public key. Subtype of @racket[xmeta].
}

@defstruct*[xpriv ([exponent exact-nonnegative-integer?])]{
 Extended private key. Subtype of @racket[xmeta].
}

@section{Serialization}

@defproc[(string->xpub [str string?]) xpub?]{
 Parses @racketfont{str} as an @racket[xpub].
}

@defproc[(xpub->string [x xpub?]) string?]{
 Converts an @racket[xpub] to its string representation.
}

@defproc[(string->xpriv [str string?]) xpriv?]{
 Parses @racketfont{str} as an @racket[xpriv].
}

@defproc[(xpriv->string [x xpriv?]) string?]{
 Converts an @racket[xpriv] to its string representation.
}

@section{Key Derivation}

@defproc[(CKDpub [x xpub?] [i exact-nonnegative-integer?]) xpub?]{
 Derives the @math{i^th} child of @racket[x]. Hardened derivations are not possible,
 so @racketfont{i} must be less than @math{2^31}.
}

@defproc[(CKDpriv [x xpriv?] [i exact-nonnegative-integer?]) xpriv?]{
 Derives the @math{i^th} child of @racket[x]. When @racketfont{i} is less than @math{2^31},
 a non-hardened derivation is performed. Otherwise, a hardened derivation is performed.

 An error will be raised if @racketfont{i} is equal to or greater than @math{2^32}.
}

@defproc[(N [x xpriv?]) xpub?]{
 Returns the public key corresponding to @racketfont{x}.
}

@section{Derivation Paths}

@defproc[(string->path [str string?]) (listof/c exact-nonnegative-integer?)]{
 Parses the path string @racketfont{str}.
}

@defproc[(xpub-derive-path [root xpub?] [path (listof/c exact-nonnegative-integer?)]) xpub?]{
 Folds @racket[CKDpub] over the elements of @racketfont{path} with initial @racket[xpub] @racketfont{root}.
}

@defproc[(xpriv-derive-path [root xpriv?] [path (listof/c exact-nonnegative-integer?)]) xpriv?]{
 Folds @racket[CKDpriv] over the elements of @racketfont{path} with initial @racket[xpriv] @racketfont{root}.
}