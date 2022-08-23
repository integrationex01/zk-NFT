package proof

import (
	"fmt"
	"image"
	_ "image/png"
	"os"

	c "ZK-NFT/circuit"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

var NFTPATH = "/root/go-work/dealpic/NFT.png"
var SECRETPATH = "/root/go-work/dealpic/NFTp2.png"
var PUBLICPATH = "/root/go-work/dealpic/NFTp1.png"

func readPic(Path string) image.Image {
	f, err := os.Open(Path)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	img, fmtName, err := image.Decode(f)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Name: %v, Bounds: %+v, Color: %+v\n", fmtName, img.Bounds(), img.ColorModel())

	return img
}

func Assignment() c.Circuit {
	// load NFT picture
	nft := readPic(NFTPATH)
	secret := readPic(SECRETPATH)
	public := readPic(PUBLICPATH)

	// create assignment
	var circuit c.Circuit
	// var builder1 strings.Builder
	for _, value := range nft.(*image.RGBA).Pix {
		// picmatrix := fmt.Sprintf("%d", int(value))
		// builder1.WriteString(picmatrix)
		// fmt.Printf("%T", int(value))
		circuit.Picture = append(circuit.Picture, value)
	}
	// circuit.Picture = builder1.String()

	// var builder2 strings.Builder
	for _, value := range secret.(*image.RGBA).Pix {
		// part1matrix := fmt.Sprintf("%d", int(value))
		// builder2.WriteString(part1matrix)
		circuit.NFTPART1 = append(circuit.NFTPART1, value)
	}
	// circuit.NFTPART1 = builder2.String()

	mimcp1 := mimc.NewMiMC()

	mimcp1.Write(secret.(*image.RGBA).Pix[:])

	circuit.Part1Hash = mimcp1.Sum([]byte(""))

	// var builder3 strings.Builder
	for _, value := range public.(*image.RGBA).Pix {
		// part2matrix := fmt.Sprintf("%d", int(value))
		// builder3.WriteString(part2matrix)
		circuit.NFTPART2 = append(circuit.NFTPART2, value)
	}
	// circuit.NFTPART2 = builder3.String()

	mimcp2 := mimc.NewMiMC()

	mimcp2.Write(public.(*image.RGBA).Pix[:])

	circuit.Part2Hash = mimcp2.Sum([]byte(""))

	return circuit
}

func ProofGroth16(ccs frontend.CompiledConstraintSystem) error {

	// groth16 zkSNARK: Setup
	// 生成prover key and vertifier key
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		fmt.Println(err.Error())
	}

	// witness definition
	assignment := Assignment()
	witness, err := frontend.NewWitness(&assignment, ecc.BN254)
	if err != nil {
		fmt.Println(err.Error())
	}
	publicWitness, _ := witness.Public()

	// groth16: Prove & Verify
	// 利用Prover Key生成Proof
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		fmt.Println(err.Error())
	}
	//利用Vertifier Key验证Proof
	err = groth16.Verify(proof, vk, publicWitness)
	return err

}
