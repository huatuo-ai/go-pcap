# Add a filter primitive

Adding a primitive changes a public filter-language contract. Treat parsing,
code generation, EN10MB/RAW behavior, and verification as one change rather
than as independent edits.

## 1. Define the language element

Start in `filter/primitives.go` and the token/enum definitions it uses. Add the
new protocol, qualifier, or primitive kind with its semantic defaults. Update
the lexer/parser mapping in `filter/expression.go` so the expression language
recognizes the word and composes it with existing qualifiers such as `src`,
`dst`, `host`, or `port` where that combination is valid.

Keep the public grammar narrow: a keyword should have one unambiguous meaning
and a documented failure mode when its operands are unsupported.

## 2. Validate inputs

Update `primitive.validate` and helper functions as needed. Return useful
errors for invalid addresses, port names, network masks, or protocol-specific
arguments. The package-level `Compile` entry point classifies malformed
expressions with `ErrInvalidFilter`, so callers can use `errors.Is` without
discarding the underlying detail.

## 3. Emit the cBPF branches

Implement the primitive's emit path in `filter/primitive.go` and reuse the
helpers in `filter/compile.go` where possible. Emit labelled match and miss
destinations; do not hand-calculate cBPF skip offsets. The program finalizer in
`filter/prog.go` resolves labels and rejects invalid control flow.

Choose the packet offset through the supplied `linkLayout`, never by assuming
a fixed Ethernet offset. Decide explicitly whether the primitive is valid for
RAW. L2-only primitives must preserve the existing RAW behavior: they reduce
to a non-match and an entirely L2-only RAW filter returns `ErrL2OnlyLinkType`.

## 4. Keep size and compile behavior aligned

`Size` must remain consistent with the instruction count produced by a
successful `Compile` for every supported layout. Add cases to the size
invariant tests when the new primitive changes instruction generation or
short-circuit behavior.

## 5. Prove accept/reject behavior

Add focused parser/compiler cases, then VM behavior and protocol-matrix cases
for both matches and non-matches. Include EN10MB and RAW expectations where
the primitive can run in both layouts. Add a tcpdump golden case only when the
expression belongs to the supported compatibility subset and a semantic
comparison is useful.

Run the commands in the [testing guide](testing.md) before submitting. Explain
the intended packet-layout semantics in the pull request, especially for
loopback or L3-only paths.
