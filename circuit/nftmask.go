package circuit

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/consensys/gnark/std/hash/mimc"
)

// Create the struct of circuit
type Circuit struct {
	NFTPART1  []frontend.Variable `gnark:"part1"`            // part1  --> secret visibility
	Part1Hash frontend.Variable   `gnark:"part1Hash,public"` // part1Hash  --> public visibility
	NFTPART2  []frontend.Variable `gnark:"part2,public"`     // part2  --> public visibility
	Part2Hash frontend.Variable   `gnark:"part2Hash,public"` // part2Hash  --> public visibility
	Picture   []frontend.Variable `gnark:"picture"`          // picture--> secret visibility
}

func (circuit *Circuit) Define(api frontend.API) error {
	// hash function
	mimcp1, _ := mimc.NewMiMC(api)
	mimcp2, _ := mimc.NewMiMC(api)
	mimcCob, _ := mimc.NewMiMC(api)
	mimcPic, _ := mimc.NewMiMC(api)

	// make sure input accuracy
	mimcp1.Write(circuit.NFTPART1[:]...)
	mimcp2.Write(circuit.NFTPART2[:]...)
	api.AssertIsEqual(mimcp1.Sum(), circuit.Part1Hash)
	api.AssertIsEqual(mimcp2.Sum(), circuit.Part2Hash)
	// add
	// var build strings.Builder
	// build.WriteString(reflect.ValueOf(circuit.NFTPART1).String())
	// build.WriteString(reflect.ValueOf(circuit.NFTPART2).String())
	// var conbine frontend.Variable
	// conbine, _ = strconv.Atoi(build.String())
	conbine := append(circuit.NFTPART1, circuit.NFTPART2...)

	// compare constraints
	mimcCob.Write(conbine[:]...)
	mimcPic.Write(circuit.Picture[:]...)

	api.AssertIsEqual(mimcCob.Sum(), mimcPic.Sum())

	return nil

}

func Compilecircuit() frontend.CompiledConstraintSystem {
	var MyCircuit Circuit
	r1cs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &MyCircuit)
	if err != nil {
		fmt.Printf("error : %s\n", err.Error())
	}
	// constraints := r1cs.GetConstraints()
	// fmt.Printf("r1cs:%v\n", r1cs)
	// fmt.Printf("the constraints are :%v\n", constraints)
	return r1cs
}
