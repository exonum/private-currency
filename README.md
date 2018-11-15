# Private Cryptocurrency Service

This is an [Exonum] service implementing privacy-preserving cryptocurrency. The service hides the amounts being
transferred among registered accounts (but not the identities transacting accounts).

**Warning.** This is a proof of concept; it has not been tested and fitted for production. Use at your own risk.

## Implementation details

The service uses [pure Rust implementation][bulletproofs-rs] for [Bulletproofs][bulletproofs], a technique allowing
to prove a range of a value hidden with the help of the [Pedersen commitment scheme][pedersen]. Commitments are used
instead of cleartext values both in account details and in transfer transactions.

### Accounts

The service uses account-based scheme similar to one used for ERC-20 tokens in Ethereum; it is also used in simpler
[demo cryptocurrency services for Exonum][demo]. Unlike other demos, each wallet contains a _commitment_ to the current
balance `Comm(bal; r)` instead of its cleartext value `bal`. Only the owner of the account knows the opening
to this commitment.

### Transfers

Each transfer transaction contains a commitment to the transferred amount `C_a = Comm(a; r)`.
It is supplied with two range proofs:

- The amount is non-negative: `a >= 0`
- The sender has sufficient balance on his account: `sender.bal >= a`

The first proof is stateless, i.e., can be verified without consulting the blockchain state.
In order to verify the second proof, it's necessary to know the commitment `C_bal` to the sender's current balance
(which is stored in her wallet info). The proof is equivalent to proving `C_bal - C_a` opens to a value
in the allowed range.

### Transfer acceptance

A natural question is how the receiver of the payment finds out about its amount `a`; by design, it is impossible
using only blockchain information. We solve this by asymmetrically encrypting the opening to `C_a` - i.e.,
pair `(a, r)` - with the help of `box` routine from `libsodium`, so it can only be decrypted by the
receiver and sender of the transfer. For simplicity, we convert Ed25519 keys used to sign transactions
to Curve25519 keys required for `box`; i.e., accounts are identified by a single Ed25519 public key.

A sender may maliciously encrypt garbage. Thus, we give the receiver a certain amount of time
after the transfer transaction is committed, to verify that she can decrypt it. To signal successful verification,
the receiver creates and sends a separate _acceptance_ transaction referencing the transfer.

The _sender's balance_ decreases immediately after the transfer transaction is committed
(recall that it is stored as a commitment, so we perform arithmetic on commitments rather than
cleartext values). The _receiver's balance_ is not changed immediately; it is only increased
(again, using commitment arithmetic) only after her appropriate acceptance transaction is committed.

To prevent deadlocks, each transfer transaction specifies the timelock parameter (in relative blockchain height,
a la Bitcoin's `CSV` opcode). If this timelock expires and the receiver of the transfer still hasn't accepted it,
the transfer is automatically refunded to the sender.

## TODO list

- [ ] Check `a > 0` instead of `a >= 0` in transfers
- [ ] Allow to reference a past commitment to sender's balance (but not before the latest outgoing transfer)
  in order to boost concurrency
- [ ] Merkelize storage data
- [ ] Index unaccepted transfers by blockchain height and filter them correspondingly in API
- [ ] Test more stuff

## Building and testing

Notice that the service requires `nightly` Rust channel as of now; the `bulletproofs` crate doesn't build otherwise.
There are some unit and integration tests and also examples. See their documentation for more details.

[Exonum]: https://exonum.com/
[bulletproofs-rs]: https://doc.dalek.rs/bulletproofs/
[bulletproofs]: https://eprint.iacr.org/2017/1066.pdf
[pedersen]: https://en.wikipedia.org/wiki/Commitment_scheme
[demo]: https://github.com/exonum/exonum/tree/master/examples