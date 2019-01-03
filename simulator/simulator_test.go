/*
 * Copyright 2018 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package simulator

import (
	"crypto/rsa"
	"io"
	"math/big"
	"testing"

	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/google/go-tpm/tpm2"
)

func getSimulator(t *testing.T) *Simulator {
	t.Helper()
	simulator, err := Get()
	if err != nil {
		t.Fatal(err)
	}
	return simulator
}

func getEKModulus(t *testing.T, rwc io.ReadWriteCloser) *big.Int {
	t.Helper()
	ek, err := tpm2tools.EndorsementKeyRSA(rwc)
	if err != nil {
		t.Fatal(err)
	}
	defer ek.Close()

	return ek.PublicKey().(*rsa.PublicKey).N
}

func TestResetDoesntChangeEK(t *testing.T) {
	s := getSimulator(t)
	defer s.Close()

	modulus1 := getEKModulus(t, s)
	if err := s.Reset(); err != nil {
		t.Fatal(err)
	}
	modulus2 := getEKModulus(t, s)

	if modulus1.Cmp(modulus2) != 0 {
		t.Fatal("Reset() should not change the EK")
	}
}
func TestManufactureResetChangesEK(t *testing.T) {
	s := getSimulator(t)
	defer s.Close()

	modulus1 := getEKModulus(t, s)
	if err := s.ManufactureReset(); err != nil {
		t.Fatal(err)
	}
	modulus2 := getEKModulus(t, s)

	if modulus1.Cmp(modulus2) == 0 {
		t.Fatal("ManufactureReset() should change the EK")
	}
}

func TestGetRandom(t *testing.T) {
	s := getSimulator(t)
	defer s.Close()
	result, err := tpm2.GetRandom(s, 10)
	if err != nil {
		t.Fatalf("GetRandom: %v", err)
	}
	t.Log(result)
}

// The default EK modulus returned by the simulator when using a seed of 0.
func zeroSeedModulus() *big.Int {
	mod := new(big.Int)
	mod.SetString("28822369077247917472678792367222000492900687607266016203396010837658035689659299734197520553448174323748099793056802958016858756507381032370846534085226253302163899570149199884764519084423882009496754412303818542106327689835389505182193570218605954083532946205386443901420426483800949411692505321722270168362120233669126618971767634850592961537085580034378654792382721745037008114868292963660065852214336139344092437160292248180730141651685121689744852235653454825312462533593592821458433769751868260970774226182524156494472225018947922698640025954940757779839947653936267356452628876700038270975372202071693935689021", 10)
	return mod
}

func TestFixedSeedExpectedModulus(t *testing.T) {
	s, err := GetWithFixedSeed(0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	modulus := getEKModulus(t, s)
	if modulus.Cmp(zeroSeedModulus()) != 0 {
		t.Fatalf("Got %v expected %v", modulus, zeroSeedModulus())
	}
}

func TestDifferentSeedDifferentModulus(t *testing.T) {
	s, err := GetWithFixedSeed(1)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	modulus := getEKModulus(t, s)
	if modulus.Cmp(zeroSeedModulus()) == 0 {
		t.Fatalf("Moduli should not be equal when using different seeds")
	}
}
