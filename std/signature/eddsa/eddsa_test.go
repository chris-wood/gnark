/*
Copyright © 2020 ConsenSys

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package eddsa

import (
	"math/big"
	"math/rand"
	"testing"
	"time"

	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	chash "github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature/eddsa"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test"
)

type eddsaCircuit struct {
	curveID   tedwards.ID
	PublicKey PublicKey         `gnark:",public"`
	Signature Signature         `gnark:",public"`
	Message   frontend.Variable `gnark:",public"`
}

func (circuit *eddsaCircuit) Define(api frontend.API) error {

	curve, err := twistededwards.NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}

	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// verify the signature in the cs
	return Verify(curve, circuit.Signature, circuit.Message, circuit.PublicKey, &mimc)
}

func TestEddsa(t *testing.T) {

	assert := test.NewAssert(t)

	type testData struct {
		hash  chash.Hash
		curve tedwards.ID
	}

	confs := []testData{
		{chash.MIMC_BN254, tedwards.BN254},
		{chash.MIMC_BLS12_381, tedwards.BLS12_381},
		// {hash.MIMC_BLS12_381, tedwards.BLS12_381_BANDERSNATCH},
		{chash.MIMC_BLS12_377, tedwards.BLS12_377},
		{chash.MIMC_BW6_761, tedwards.BW6_761},
		{chash.MIMC_BLS24_315, tedwards.BLS24_315},
		{chash.MIMC_BLS24_317, tedwards.BLS24_317},
		{chash.MIMC_BW6_633, tedwards.BW6_633},
	}

	bound := 5
	if testing.Short() {
		bound = 1
	}

	for i := 0; i < bound; i++ {
		seed := time.Now().Unix()
		t.Logf("setting seed in rand %d", seed)
		randomness := rand.New(rand.NewSource(seed)) //#nosec G404 -- This is a false positive

		for _, conf := range confs {

			snarkField, err := twistededwards.GetSnarkField(conf.curve)
			assert.NoError(err)
			snarkCurve := utils.FieldToCurve(snarkField)

			// generate parameters for the signatures
			privKey, err := eddsa.New(conf.curve, randomness)
			assert.NoError(err, "generating eddsa key pair")

			// pick a message to sign
			var msg big.Int
			msg.Rand(randomness, snarkField)
			t.Log("msg to sign", msg.String())
			msgDataUnpadded := msg.Bytes()
			msgData := make([]byte, len(snarkField.Bytes()))
			copy(msgData[len(msgData)-len(msgDataUnpadded):], msgDataUnpadded)

			// generate signature
			signature, err := privKey.Sign(msgData, conf.hash.New())
			assert.NoError(err, "signing message")

			// check if there is no problem in the signature
			pubKey := privKey.Public()
			checkSig, err := pubKey.Verify(signature, msgData, conf.hash.New())
			assert.NoError(err, "verifying signature")
			assert.True(checkSig, "signature verification failed")

			// create and compile the circuit for signature verification
			var circuit eddsaCircuit
			circuit.curveID = conf.curve

			// verification with the correct Message
			{
				var witness eddsaCircuit
				witness.Message = msg
				witness.PublicKey.Assign(conf.curve, pubKey.Bytes())
				witness.Signature.Assign(conf.curve, signature)

				assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(snarkCurve))
			}

			// verification with incorrect Message
			{
				var witness eddsaCircuit

				msg.Rand(randomness, snarkField)
				witness.Message = msg
				witness.PublicKey.Assign(conf.curve, pubKey.Bytes())
				witness.Signature.Assign(conf.curve, signature)

				assert.SolvingFailed(&circuit, &witness, test.WithCurves(snarkCurve))
			}

		}
	}
}

// Issuance:
//  Client: Create state (nonce, timestamp, zero counter), commitment to state, and ZKP(counter == 0, timestamp matches)
//  Issuer: Verify ZKP and sign the commitment

// Redemption
//  Client: Create state (nonce', timestamp, counter+1), commitment to state, ZKP(know signature over old commitment with nonce, counter++, timestamp matches, counter < LIMIT), old nonce
//  Origin: Verify ZKP and sign the commitment

type rateLimitedTokenCircuit struct {
	curveID              tedwards.ID
	CommitmentRandomizer frontend.Variable `gnark:"commitment_randomizer"`
	Nonce                frontend.Variable `gnark:"nonce"`
	Counter              frontend.Variable `gnark:"counter"`
	Commitment           frontend.Variable `gnark:"commitment,public"`
}

func (circuit *rateLimitedTokenCircuit) Define(api frontend.API) error {
	curve, err := twistededwards.NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}

	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// Assert that the counter is 0
	isZero := curve.API().IsZero(circuit.Counter)
	curve.API().AssertIsEqual(isZero, 1)

	// Assert that the commitment matches the public witness
	hash := &mimc
	hash.Write(circuit.CommitmentRandomizer)
	hash.Write(circuit.Nonce)
	hash.Write(circuit.Counter)
	digest := hash.Sum()
	curve.API().AssertIsEqual(digest, circuit.Commitment)

	return nil
}

type updatedRateLimitedTokenCircuit struct {
	curveID tedwards.ID

	// Old state
	PreviousCommitmentRandomizer frontend.Variable `gnark:"prev_commitment_randomizer"`
	PreviousCounter              frontend.Variable `gnark:"prev_counter"`
	PreviousCommitment           frontend.Variable `gnark:"prev_commitment"`
	PreviousNonce                frontend.Variable `gnark:"prev_nonce,public"`

	// New state
	CommitmentRandomizer frontend.Variable `gnark:"commitment_randomizer"`
	Nonce                frontend.Variable `gnark:"nonce"`
	Counter              frontend.Variable `gnark:"counter"`
	Commitment           frontend.Variable `gnark:"commitment,public"`

	// Verification information over old state
	OriginKey    PublicKey `gnark:"origin_key,public"`
	IssuerKey    PublicKey `gnark:"issuer_key,public"`
	VerifyingKey PublicKey `gnark:"verifying_key"`
	Signature    Signature `gnark:"signature"`
}

// ZKP(know signature over old commitment with nonce, counter++, counter < LIMIT)
func (circuit *updatedRateLimitedTokenCircuit) Define(api frontend.API) error {
	curve, err := twistededwards.NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}

	hasher, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// Assert that the signature over the counter is valid
	Verify(curve, circuit.Signature, circuit.PreviousCommitment, circuit.VerifyingKey, &hasher)

	// Assert that the verification key is either the issuer's or the origin's, but don't reveal which one
	isIssuerCompareX := curve.API().Cmp(circuit.VerifyingKey.A.X, circuit.IssuerKey.A.X)
	isIssuerCompareXResult := curve.API().IsZero(isIssuerCompareX)
	isIssuerCompareY := curve.API().Cmp(circuit.VerifyingKey.A.Y, circuit.IssuerKey.A.Y)
	isIssuerCompareYResult := curve.API().IsZero(isIssuerCompareY)
	isIssuerCompare := curve.API().And(isIssuerCompareXResult, isIssuerCompareYResult) // isIssuerCompare = (X == X) & (Y == Y)

	isOriginCompareX := curve.API().Cmp(circuit.VerifyingKey.A.X, circuit.OriginKey.A.X)
	isOriginCompareXResult := curve.API().IsZero(isOriginCompareX)
	isOriginCompareY := curve.API().Cmp(circuit.VerifyingKey.A.Y, circuit.OriginKey.A.Y)
	isOriginCompareYResult := curve.API().IsZero(isOriginCompareY)
	isOriginCompare := curve.API().And(isOriginCompareXResult, isOriginCompareYResult) // isOriginCompare = (X == X) || (Y == Y)

	eitherOr := curve.API().Or(isIssuerCompare, isOriginCompare) // eitherOr = 1 iff (isIssuerCompare == 1 || isOriginCompare == 1)
	curve.API().AssertIsEqual(eitherOr, 1)

	// Assert that the counter is an updated version of the previous counter
	newCounter := curve.API().Add(circuit.PreviousCounter, 1)
	curve.API().AssertIsEqual(newCounter, circuit.Counter)

	// Assert that the counter is less than CONSTANT (=1 for testing purposes)
	curve.API().AssertIsLessOrEqual(circuit.Counter, 1)

	// Assert that the old commitment matches the old values
	hasher, err = mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	hash := &hasher
	hash.Write(circuit.PreviousCommitmentRandomizer)
	hash.Write(circuit.PreviousNonce)
	hash.Write(circuit.PreviousCounter)
	digest := hash.Sum()
	curve.API().AssertIsEqual(digest, circuit.PreviousCommitment)

	// Assert that the commitment matches the public witness
	hasher, err = mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	hash = &hasher
	hash.Write(circuit.CommitmentRandomizer)
	hash.Write(circuit.Nonce)
	hash.Write(circuit.Counter)
	digest = hash.Sum()
	curve.API().AssertIsEqual(digest, circuit.Commitment)

	return nil
}

func TestMyCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	hash := chash.MIMC_BN254
	curve := tedwards.BN254

	snarkField, err := twistededwards.GetSnarkField(curve)
	assert.NoError(err)
	snarkCurve := utils.FieldToCurve(snarkField)

	randomness := rand.New(rand.NewSource(0))

	// Generate the issuer key pair
	issuerPrivateKey, err := eddsa.New(curve, randomness)
	assert.NoError(err, "generating issuer key pair")

	// Generate the origin key pair
	originPrivateKey, err := eddsa.New(curve, randomness)
	assert.NoError(err, "generating origin key pair")

	// Initial state: a random nonce and counter set to 0
	var nonce big.Int
	nonce.Rand(randomness, snarkField)
	var counter big.Int
	counter.SetUint64(0)

	// Compute the commitment to this state
	buffer := make([]byte, 32) // XXX(caw): get the size of the underlying field rather than assume 32 bytes here
	var commitmentRandomizer big.Int
	commitmentRandomizer.Rand(randomness, snarkField)
	mimc := hash.New()
	commitmentRandomizer.FillBytes(buffer)
	mimc.Write(buffer)
	nonce.FillBytes(buffer)
	mimc.Write(buffer)
	counter.FillBytes(buffer)
	mimc.Write(buffer)
	commitment := mimc.Sum(nil)

	var circuit rateLimitedTokenCircuit
	circuit.curveID = curve

	// Construct the witness for verification
	var witness rateLimitedTokenCircuit
	witness.CommitmentRandomizer = commitmentRandomizer
	witness.Nonce = nonce
	witness.Counter = counter
	witness.Commitment = commitment

	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(snarkCurve))

	// Setup the proof system
	cs, err := frontend.Compile(snarkField, r1cs.NewBuilder, &circuit)
	assert.Nil(err)
	pk, vk, err := groth16.Setup(cs)
	assert.Nil(err)

	// Create the proof of the initial token state
	assignment := &rateLimitedTokenCircuit{
		curveID:              curve,
		CommitmentRandomizer: commitmentRandomizer,
		Nonce:                nonce,
		Counter:              counter,
		Commitment:           commitment,
	}
	proofWitness, err := frontend.NewWitness(assignment, snarkField)
	assert.Nil(err)
	proof, err := groth16.Prove(cs, pk, proofWitness)
	assert.Nil(err)

	// Verify the proof
	publicWitness, err := proofWitness.Public()
	assert.Nil(err)
	err = groth16.Verify(proof, vk, publicWitness)
	assert.Nil(err)

	// Sign the commitment
	signature, err := issuerPrivateKey.Sign(commitment, hash.New())
	assert.NoError(err, "signing message")

	// check if there is no problem in the signature
	pubKey := issuerPrivateKey.Public()
	checkSig, err := pubKey.Verify(signature, commitment, hash.New())
	assert.NoError(err, "verifying signature")
	assert.True(checkSig, "signature verification failed")

	// Now do redemption... create a new state
	var newNonce big.Int
	newNonce.Rand(randomness, snarkField)
	var newCounter big.Int
	newCounter.SetUint64(counter.Uint64() + 1)

	// Compute commitment to this new state
	var newCommitmentRandomizer big.Int
	newCommitmentRandomizer.Rand(randomness, snarkField)
	newMimc := hash.New()
	newCommitmentRandomizer.FillBytes(buffer)
	newMimc.Write(buffer)
	newNonce.FillBytes(buffer)
	newMimc.Write(buffer)
	newCounter.FillBytes(buffer)
	newMimc.Write(buffer)
	newCommitment := newMimc.Sum(nil)

	// Create:
	// - new state (nonce', counter+1)
	// - commitment to new state
	// - ZKP(know signature over old commitment with nonce, counter += 1, counter < LIMIT)
	var updatedCircuit updatedRateLimitedTokenCircuit
	updatedCircuit.curveID = curve

	// Construct the witness for verification of the updated token state
	var updatedWitness updatedRateLimitedTokenCircuit
	updatedWitness.curveID = curve
	updatedWitness.PreviousCommitmentRandomizer = commitmentRandomizer
	updatedWitness.PreviousCounter = counter
	updatedWitness.PreviousCommitment = commitment
	updatedWitness.PreviousNonce = nonce // make the old nonce public to the verifier
	updatedWitness.CommitmentRandomizer = newCommitmentRandomizer
	updatedWitness.Nonce = newNonce
	updatedWitness.Counter = newCounter
	updatedWitness.Commitment = newCommitment
	updatedWitness.VerifyingKey.Assign(curve, pubKey.Bytes())
	updatedWitness.OriginKey.Assign(curve, originPrivateKey.Public().Bytes())
	updatedWitness.IssuerKey.Assign(curve, issuerPrivateKey.Public().Bytes())
	updatedWitness.Signature.Assign(curve, signature)

	// Check that it succeeds
	assert.SolvingSucceeded(&updatedCircuit, &updatedWitness, test.WithCurves(snarkCurve))

	// Send:
	// - old state nonce (this is sent in the witness for the proof)
	// - new state (this is sent in the witness)
	// - ZKP (this is part of the proof)

	// Setup the proof system
	cs, err = frontend.Compile(snarkField, r1cs.NewBuilder, &updatedCircuit)
	assert.Nil(err)
	pk, vk, err = groth16.Setup(cs)
	assert.Nil(err)

	// Create the proof of the initial token state
	newAssignment := &updatedRateLimitedTokenCircuit{
		curveID:                      curve,
		PreviousCommitmentRandomizer: commitmentRandomizer,
		PreviousCounter:              counter,
		PreviousCommitment:           commitment,
		PreviousNonce:                nonce,
		CommitmentRandomizer:         newCommitmentRandomizer,
		Nonce:                        newNonce,
		Counter:                      newCounter,
		Commitment:                   newCommitment,
	}
	newAssignment.VerifyingKey.Assign(curve, pubKey.Bytes())
	newAssignment.OriginKey.Assign(curve, originPrivateKey.Public().Bytes())
	newAssignment.IssuerKey.Assign(curve, issuerPrivateKey.Public().Bytes())
	newAssignment.Signature.Assign(curve, signature)
	proofWitness, err = frontend.NewWitness(newAssignment, snarkField)
	assert.Nil(err)
	proof, err = groth16.Prove(cs, pk, proofWitness)
	assert.Nil(err)

	// Verify the proof
	publicWitness, err = proofWitness.Public()
	assert.Nil(err)
	err = groth16.Verify(proof, vk, publicWitness)
	assert.Nil(err)

	// Sign the commitment
	updatedSignature, err := originPrivateKey.Sign(newCommitment, hash.New())
	assert.NoError(err, "signing message")

	// XXX(caw): update the state again, but this time fail because the limit was hit

	var finalNonce big.Int
	finalNonce.Rand(randomness, snarkField)
	var finalCounter big.Int
	finalCounter.SetUint64(newCounter.Uint64() + 1)

	// Compute commitment to this new state
	var finalCommitmentRandomizer big.Int
	finalCommitmentRandomizer.Rand(randomness, snarkField)
	finalMimc := hash.New()
	finalCommitmentRandomizer.FillBytes(buffer)
	finalMimc.Write(buffer)
	finalNonce.FillBytes(buffer)
	finalMimc.Write(buffer)
	newCounter.FillBytes(buffer)
	finalMimc.Write(buffer)
	finalCommitment := finalMimc.Sum(nil)

	// Create:
	// - new state (nonce', counter+1)
	// - commitment to new state
	// - ZKP(know signature over old commitment with nonce, counter += 1, counter < LIMIT)
	var finalCircuit updatedRateLimitedTokenCircuit
	finalCircuit.curveID = curve

	// Construct the witness for verification of the updated token state
	var finalWitness updatedRateLimitedTokenCircuit
	finalWitness.curveID = curve
	finalWitness.PreviousCommitmentRandomizer = newCommitmentRandomizer
	finalWitness.PreviousCounter = newCounter
	finalWitness.PreviousCommitment = newCommitment
	finalWitness.PreviousNonce = newNonce // make the old nonce public to the verifier
	finalWitness.CommitmentRandomizer = finalCommitmentRandomizer
	finalWitness.Nonce = finalNonce
	finalWitness.Counter = finalCounter
	finalWitness.Commitment = finalCommitment
	finalWitness.VerifyingKey.Assign(curve, originPrivateKey.Public().Bytes())
	finalWitness.OriginKey.Assign(curve, originPrivateKey.Public().Bytes())
	finalWitness.IssuerKey.Assign(curve, issuerPrivateKey.Public().Bytes())
	finalWitness.Signature.Assign(curve, updatedSignature)

	// Check that it fails (since the limit is hit)
	assert.SolvingSucceeded(&finalCircuit, &finalWitness, test.WithCurves(snarkCurve))
}
