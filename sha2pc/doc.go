// Package sha2pc implements a self-contained two-party protocol for
// computing SHA256(XOR(a,b)) without embedding any networking code.
// Each party drives the protocol by invoking the exported round
// methods and relaying the opaque message blobs to its peer. The
// package hides all MPC internal details (garbled circuits, oblivious
// transfers, etc.) while keeping the message ordering explicit.
//
// Example usage:
//
//	garbler, _ := sha2pc.NewGarbler(nil)
//	evaluator, _ := sha2pc.NewEvaluator(nil)
//
//	var a, b [32]byte
//	for i := 0; i < len(a); i++ {
//		a[i] = byte(i)
//		b[i] = byte(len(a) - i)
//	}
//
//	msg1, _ := garbler.Round1(a)
//	msg2, _ := evaluator.Round2(msg1, b)
//	msg3, _ := garbler.Round3(msg2)
//	hashEval, msg4, _ := evaluator.Round4(msg3)
//	hashGar, _ := garbler.Finalize(msg4)
//
//	_ = hashEval
//	_ = hashGar
package sha2pc
