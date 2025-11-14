# sha2pc

`sha2pc` is a pure-Go two-party protocol that privately computes
`SHA256(XOR(a, b))` for two 32-byte inputs. The package exposes
deterministic round handlers instead of network stacks, so callers can
exchange the opaque `Message` values using any transport they like
(sockets, gRPC, files, etc.).

## Example

```go
package main

import (
	"fmt"

	"github.com/markkurossi/mpc/sha2pc"
)

func main() {
	garbler, _ := sha2pc.NewGarbler(nil)
	evaluator, _ := sha2pc.NewEvaluator(nil)

	var a, b [32]byte
	for i := 0; i < len(a); i++ {
		a[i] = byte(i)
		b[i] = byte(len(a) - i)
	}

	msg1, _ := garbler.Round1(a)
	msg2, _ := evaluator.Round2(msg1, b)
	msg3, _ := garbler.Round3(msg2)
	hashEval, msg4, _ := evaluator.Round4(msg3)
	hashGar, _ := garbler.Finalize(msg4)

	fmt.Printf("Evaluator hash: %x\n", hashEval)
	fmt.Printf("Garbler hash:   %x\n", hashGar)
}
```
