// Package sha2pc implements a self-contained two-party protocol for
// computing SHA256(XOR(a,b)) without embedding any networking code.
// Each party drives the protocol by invoking the exported round
// methods and relaying the opaque message blobs to its peer.  The
// package hides all MPC internal details (garbled circuits, oblivious
// transfers, etc.) while keeping the message ordering explicit.
package sha2pc
