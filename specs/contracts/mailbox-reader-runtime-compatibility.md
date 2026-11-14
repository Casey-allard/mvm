# Mailbox reader runtime compatibility

Backing: shipped-source
Validation: check-all

A runtime assembly may contain `mailbox_reader_v1`. This compatibility
information is not permission to launch, enroll, send, receive, or access a
mailbox. Canonical admission, signed mailbox grants, original boot binding,
current parent ownership, and backend checks remain required.

The optional object contains `format` equal to 1, a nonzero `max_boot_bytes`,
and a duplicate-free `features` array. Its closed feature vocabulary is
`directed_journal_v1`, `object_pair_v1`, and `sender_ordinal_v1`.
`sender_ordinal_v1` requires `directed_journal_v1`. Unknown fields, unknown
features, and other format values are refused. An absent object means the
historical 2,048-byte reader with none of those extensions; absence does not
mean that the host's current reader capabilities apply to an older guest.
The host also retains its independent 8,192-byte reader limit.

Either incoming journal policy selection or an outbound journal direction
requires directed-journal support. This includes incoming grants whose boot
binding has no additional JSON fields. Object-pair selection requires
object-pair support, and outbound ordinal settlement additionally requires
sender-ordinal support. Before publishing a boot binding, the host checks the
actual original binding against its plan and compares its exact serialized
JSON byte length with both the runtime and host limits. Compatibility checks
do not weaken grant validation or infer authority from a digest.

For release runtimes the optional object is part of the assembly declaration
inside the authenticated guest archive manifest. Release proof and exact
artifact selection remain required. Arbitrary archive-member assembly does
not discover reader semantics and therefore emits no reader profile.
Only the canonical current-source producer labels newly captured guest
artifacts: it checks the producer's compiled protocol, reader, reader parser,
and mailbox grant inputs against the selected checkout, builds through the
existing source-fingerprinted guest builders, assembles the captured bytes,
and repeats source checks and fresh fingerprint walks before publication.
The profile is covered by the containing archive's normal integrity and
release-signature mechanisms; it does not create publisher authority.

The contributor source-runtime verifier retains its existing explicit
unsigned trust class. A profile in that class must match the current compiled
reader profile and the selected checkout's guest/SDK fingerprints, after the
normal source-cache archive/member checks and byte-assembly comparison.
A checked source profile never becomes authenticated release evidence.
Legacy archives remain usable where the historical reader contract suffices;
a selected extension that cannot be established is refused before execution.
