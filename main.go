package main

import (
	c "ZK-NFT/circuit"
	p "ZK-NFT/proof"
	"fmt"
)

func main() {
	css := c.Compilecircuit()
	constraints := css.GetConstraints()
	fmt.Printf("the constraint is %v\n", constraints)
	err := p.ProofGroth16(css)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("证明成功\n")

}
