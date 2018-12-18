# Implementation details

The service uses [pure Rust implementation][bulletproofs-rs] for [Bulletproofs][bulletproofs],
a technique allowing to prove a range of a value hidden with the help of
the [Pedersen commitment scheme][pedersen]. Commitments are used
instead of values both in account details and in transfer transactions.

## Accounts

The service uses account-based scheme similar to one used for ERC-20 tokens in Ethereum;
it is also used in simpler [demo cryptocurrency services for Exonum][demo].
Unlike other demos, each wallet contains a _commitment_ to the current
balance `Comm(bal; r)` instead of its plaintext value `bal`. Only the owner of the account
knows the opening to this commitment.

## Transfers

Each transfer transaction contains a commitment to the transferred amount `C_a = Comm(a; r)`.
It is supplied with two range proofs:

- The amount is positive: `a > 0`
- The sender has sufficient balance on his account: `sender.bal >= a`

The first proof is stateless, i.e., can be verified without consulting the blockchain state.
In order to verify the second proof, it’s necessary to know the commitment `C_bal`
to the sender’s current balance (which is stored in her wallet info). The proof is equivalent
to proving `C_bal - C_a` opens to a value in the allowed range.

## Transfer acceptance

A natural question is how the receiver of the payment finds out about its amount `a`;
by design, it is impossible using only blockchain information. We solve this
by asymmetrically encrypting the opening to `C_a` – i.e., pair `(a, r)` –
with the help of `box` routine from `libsodium`, so it can only be decrypted by the
receiver and sender of the transfer. For simplicity, we convert Ed25519 keys used
to sign transactions to Curve25519 keys required for `box`; i.e., accounts are identified
by a single Ed25519 public key.

A sender may maliciously encrypt garbage. Thus, we give the receiver a certain amount of time
after the transfer transaction is committed, to verify that she can decrypt it.
To signal successful verification, the receiver creates and sends a separate _acceptance_
transaction referencing the transfer.

The _sender’s balance_ decreases immediately after the transfer transaction is committed
(recall that it is stored as a commitment, so we perform arithmetic on commitments rather than
plaintext values). The _receiver’s balance_ is not changed immediately; it is only increased
(again, using commitment arithmetic) only after her appropriate acceptance transaction
is committed.

To prevent deadlocks, each transfer transaction specifies the timelock parameter
(in relative blockchain height, a la Bitcoin’s `CSV` opcode). If this timelock expires
and the receiver of the transfer still hasn’t accepted it,
the transfer is automatically refunded to the sender.

### Referencing past wallet states

The scheme described above is *almost* practical, except for one thing:
the sender might not now her balance precisely at the moment of transfer!
Indeed, it might happen that the sender’s stray accept transaction or a refund
are processed just before the sender’s transfer (but after the transfer has been created,
signed and sent to the network). Hence, if we simply retrieve the sender’s balance from
the blockchain state during transaction execution, there is a good chance it will differ
from the one the sender had in mind when creating the sufficient balance proof.

In order to alleviate this problem, we allow the sender to specify what she thinks
is the length of her wallet history `history_len`. The proof of sufficient balance
is then checked against the balance commitment at this point in history.
For this scheme to be safe, we demand that `history_len - 1 >= last_send_index`,
where `last_send_index` is the index of the latest outgoing transfer in the sender’s history
(we track `last_send_index` directly in the sender’s account details).
If this inequality holds, it’s safe to process the transfer; we know for sure that since
`last_send_index` the sender’s balance can only increase (via incoming transfers
and/or refunds). Thus, if we subtract the transfer amount from the sender’s *current* balance,
we still end up with non-negative balance.

## Limitations

Even with heuristics described above, the scheme is limiting: before making a transfer,
the sender needs to know that there are no other unconfirmed outgoing transfers. This problem
could be solved with auto-increment counters *a la* Ethereum, or other means to order
transactions originating from the same user. This is outside the scope of this PoC.

[bulletproofs]: https://eprint.iacr.org/2017/1066.pdf
[bulletproofs-rs]: https://doc.dalek.rs/bulletproofs/
[bulletproofs]: https://eprint.iacr.org/2017/1066.pdf
[pedersen]: https://en.wikipedia.org/wiki/Commitment_scheme
[demo]: https://github.com/exonum/exonum/tree/master/examples
